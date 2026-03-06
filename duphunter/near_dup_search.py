from __future__ import annotations

import argparse
import ast
import copy
import fnmatch
import hashlib
import json
import os
import random
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from itertools import combinations
from pathlib import Path
from typing import Any

MASK_64 = (1 << 64) - 1
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+")
DEFAULT_EXCLUDES = (
    "*/.git/*",
    "*/.venv/*",
    "*/venv/*",
    "*/__pycache__/*",
    "*/node_modules/*",
    "*/site-packages/*",
)
SENSITIVITY_PRESETS: dict[str, dict[str, int]] = {
    "low": {"min_lines": 8, "min_tokens": 35},
    "medium": {"min_lines": 6, "min_tokens": 25},
    "high": {"min_lines": 4, "min_tokens": 16},
}
FUNCTION_NODE_TYPES = frozenset({"FunctionDef", "AsyncFunctionDef"})

RNG = random.Random(0xA17EA5)


def _stable_u64(text: str) -> int:
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest(), "big")


def _compile_hash_coefficients(num_perm: int) -> list[tuple[int, int]]:
    coeffs: list[tuple[int, int]] = []
    for _ in range(num_perm):
        a = RNG.randrange(1, MASK_64, 2)
        b = RNG.randrange(0, MASK_64)
        coeffs.append((a, b))
    return coeffs


@dataclass(frozen=True)
class CodeBlock:
    block_id: int
    path: str
    qualname: str
    node_type: str
    start_line: int
    end_line: int
    line_count: int
    normalized_source: str
    tokens: tuple[str, ...]
    shingles: frozenset[int]
    signature: tuple[int, ...]
    canonical_names: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class Match:
    left: CodeBlock
    right: CodeBlock
    score: float
    jaccard: float
    sequence_ratio: float
    token_overlap: float
    identifier_renames: dict[str, str]

    def to_dict(self, include_snippets: bool = False, snippet_max_chars: int = 500) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "score": round(self.score, 6),
            "jaccard": round(self.jaccard, 6),
            "sequence_ratio": round(self.sequence_ratio, 6),
            "token_overlap": round(self.token_overlap, 6),
            "identifier_renames": self.identifier_renames,
            "left": {
                "path": self.left.path,
                "qualname": self.left.qualname,
                "node_type": self.left.node_type,
                "start_line": self.left.start_line,
                "end_line": self.left.end_line,
                "line_count": self.left.line_count,
            },
            "right": {
                "path": self.right.path,
                "qualname": self.right.qualname,
                "node_type": self.right.node_type,
                "start_line": self.right.start_line,
                "end_line": self.right.end_line,
                "line_count": self.right.line_count,
            },
        }
        if include_snippets:
            payload["left"]["normalized_snippet"] = self.left.normalized_source[:snippet_max_chars]
            payload["right"]["normalized_snippet"] = self.right.normalized_source[:snippet_max_chars]
        return payload


class LocalNameCanonicalizer(ast.NodeTransformer):
    """Normalize local identifiers while preserving external call names."""

    def __init__(self, normalize_literals: bool = True) -> None:
        self.normalize_literals = normalize_literals
        self.mapping: dict[str, str] = {}
        self.reverse_mapping: dict[str, set[str]] = defaultdict(set)
        self.global_like_names: set[str] = set()
        self.counter = 0

    def _canon_for(self, raw_name: str) -> str:
        if raw_name in self.global_like_names:
            return raw_name
        if raw_name not in self.mapping:
            canon = f"__v{self.counter}"
            self.counter += 1
            self.mapping[raw_name] = canon
            self.reverse_mapping[canon].add(raw_name)
        return self.mapping[raw_name]

    def visit_Global(self, node: ast.Global) -> ast.AST:
        self.global_like_names.update(node.names)
        return node

    def visit_Nonlocal(self, node: ast.Nonlocal) -> ast.AST:
        self.global_like_names.update(node.names)
        return node

    def visit_arg(self, node: ast.arg) -> ast.AST:
        canon = self._canon_for(node.arg)
        node.arg = canon
        if node.annotation is not None:
            node.annotation = self.visit(node.annotation)
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            node.id = self._canon_for(node.id)
            return node
        if node.id in self.mapping:
            node.id = self.mapping[node.id]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.name = "__func__"
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        node.args = self.visit(node.args)
        if node.returns is not None:
            node.returns = self.visit(node.returns)
        node.body = _drop_docstring(node.body)
        node.body = [self.visit(stmt) for stmt in node.body]
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.name = "__func__"
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        node.args = self.visit(node.args)
        if node.returns is not None:
            node.returns = self.visit(node.returns)
        node.body = _drop_docstring(node.body)
        node.body = [self.visit(stmt) for stmt in node.body]
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not self.normalize_literals:
            return node
        value = node.value
        if isinstance(value, str):
            node.value = "__STR__"
        elif isinstance(value, bytes):
            node.value = b"__BYTES__"
        elif isinstance(value, (int, float, complex)):
            node.value = 0
        return node


def _drop_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if not body:
        return body
    first = body[0]
    if isinstance(first, ast.Expr):
        value = getattr(first, "value", None)
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return body[1:]
    return body


class BlockExtractor(ast.NodeVisitor):
    def __init__(
        self,
        path: str,
        source: str,
        include_classes: bool,
        include_nested: bool,
        min_lines: int,
        min_tokens: int,
        shingle_size: int,
        num_perm: int,
        hash_coeffs: list[tuple[int, int]],
        normalize_literals: bool,
    ) -> None:
        self.path = path
        self.source = source
        self.include_classes = include_classes
        self.include_nested = include_nested
        self.min_lines = min_lines
        self.min_tokens = min_tokens
        self.shingle_size = shingle_size
        self.num_perm = num_perm
        self.hash_coeffs = hash_coeffs
        self.normalize_literals = normalize_literals
        self.blocks: list[CodeBlock] = []
        self.name_stack: list[str] = []
        self.function_depth = 0

    def _qualname(self, leaf_name: str) -> str:
        if self.name_stack:
            return ".".join(self.name_stack + [leaf_name])
        return leaf_name

    def _build_block(self, node: ast.AST, qualname: str, node_type: str) -> None:
        start_line = int(getattr(node, "lineno", 0) or 0)
        end_line = int(getattr(node, "end_lineno", start_line) or start_line)
        line_count = max(1, end_line - start_line + 1)
        if line_count < self.min_lines:
            return

        normalized_source, tokens, canonical_names = _normalize_node(
            node, normalize_literals=self.normalize_literals
        )
        if len(tokens) < self.min_tokens:
            return
        shingles = _build_shingles(tokens, self.shingle_size)
        signature = _minhash_signature(shingles, self.hash_coeffs, self.num_perm)
        self.blocks.append(
            CodeBlock(
                block_id=-1,
                path=self.path,
                qualname=qualname,
                node_type=node_type,
                start_line=start_line,
                end_line=end_line,
                line_count=line_count,
                normalized_source=normalized_source,
                tokens=tuple(tokens),
                shingles=frozenset(shingles),
                signature=signature,
                canonical_names=canonical_names,
            )
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if self.include_classes:
            self._build_block(node, self._qualname(node.name), "ClassDef")
        self.name_stack.append(node.name)
        self.generic_visit(node)
        self.name_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        is_nested_function = self.function_depth > 0
        if self.include_nested or not is_nested_function:
            self._build_block(node, self._qualname(node.name), "FunctionDef")
        self.name_stack.append(node.name)
        self.function_depth += 1
        self.generic_visit(node)
        self.function_depth -= 1
        self.name_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        is_nested_function = self.function_depth > 0
        if self.include_nested or not is_nested_function:
            self._build_block(node, self._qualname(node.name), "AsyncFunctionDef")
        self.name_stack.append(node.name)
        self.function_depth += 1
        self.generic_visit(node)
        self.function_depth -= 1
        self.name_stack.pop()


def _normalize_node(node: ast.AST, normalize_literals: bool) -> tuple[str, list[str], dict[str, tuple[str, ...]]]:
    node_copy = copy.deepcopy(node)
    transformer = LocalNameCanonicalizer(normalize_literals=normalize_literals)
    normalized_node = transformer.visit(node_copy)
    ast.fix_missing_locations(normalized_node)
    try:
        normalized_source = ast.unparse(normalized_node)
    except Exception:
        normalized_source = ast.dump(normalized_node, annotate_fields=False, include_attributes=False)
    tokens = TOKEN_RE.findall(normalized_source)
    canonical_names = {k: tuple(sorted(v)) for k, v in transformer.reverse_mapping.items()}
    return normalized_source, tokens, canonical_names


def _build_shingles(tokens: list[str], shingle_size: int) -> set[int]:
    if not tokens:
        return set()
    if len(tokens) <= shingle_size:
        return {_stable_u64(" ".join(tokens))}
    shingles: set[int] = set()
    stop = len(tokens) - shingle_size + 1
    for i in range(stop):
        shingles.add(_stable_u64(" ".join(tokens[i : i + shingle_size])))
    return shingles


def _minhash_signature(shingles: set[int], coeffs: list[tuple[int, int]], num_perm: int) -> tuple[int, ...]:
    if not shingles:
        return tuple(0 for _ in range(num_perm))
    values: list[int] = []
    for a, b in coeffs:
        m = MASK_64
        for sh in shingles:
            hv = (a * sh + b) & MASK_64
            if hv < m:
                m = hv
        values.append(m)
    return tuple(values)


def _band_keys(signature: tuple[int, ...], bands: int) -> list[tuple[int, int]]:
    rows = len(signature) // bands
    keys: list[tuple[int, int]] = []
    for b in range(bands):
        start = b * rows
        end = start + rows
        chunk = signature[start:end]
        text = ",".join(str(v) for v in chunk)
        keys.append((b, _stable_u64(text)))
    return keys


def _jaccard(a: frozenset[int], b: frozenset[int]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _token_overlap(a: tuple[str, ...], b: tuple[str, ...]) -> float:
    sa = set(a)
    sb = set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


def _identifier_mapping(a: CodeBlock, b: CodeBlock) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for canon in sorted(set(a.canonical_names) & set(b.canonical_names)):
        left_names = a.canonical_names.get(canon, ())
        right_names = b.canonical_names.get(canon, ())
        if len(left_names) == 1 and len(right_names) == 1:
            left = left_names[0]
            right = right_names[0]
            if left != right:
                mapping[left] = right
    return mapping


def _compute_match(a: CodeBlock, b: CodeBlock) -> Match:
    jaccard = _jaccard(a.shingles, b.shingles)
    seq = SequenceMatcher(None, a.normalized_source, b.normalized_source, autojunk=False).ratio()
    overlap = _token_overlap(a.tokens, b.tokens)
    score = 0.65 * jaccard + 0.25 * seq + 0.10 * overlap
    return Match(
        left=a,
        right=b,
        score=score,
        jaccard=jaccard,
        sequence_ratio=seq,
        token_overlap=overlap,
        identifier_renames=_identifier_mapping(a, b),
    )


def _norm_path(p: Path) -> str:
    return str(p.resolve())


def _should_skip(path: str, excludes: tuple[str, ...]) -> bool:
    path_posix = path.replace(os.sep, "/")
    return any(fnmatch.fnmatch(path_posix, pat) for pat in excludes)


def _iter_python_files(paths: list[str], includes: tuple[str, ...], excludes: tuple[str, ...]) -> list[Path]:
    seen: set[Path] = set()
    found: list[Path] = []
    for raw in paths:
        p = Path(raw).resolve()
        if not p.exists():
            continue
        if p.is_file():
            rel = p.name
            if any(fnmatch.fnmatch(rel, pat) for pat in includes) and not _should_skip(str(p), excludes):
                if p not in seen:
                    seen.add(p)
                    found.append(p)
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if not _should_skip(str(Path(root) / d), excludes)]
            for file_name in files:
                if not any(fnmatch.fnmatch(file_name, pat) for pat in includes):
                    continue
                file_path = Path(root) / file_name
                full = _norm_path(file_path)
                if _should_skip(full, excludes):
                    continue
                resolved = Path(full)
                if resolved not in seen:
                    seen.add(resolved)
                    found.append(resolved)
    found.sort()
    return found


def _extract_blocks_from_file(
    file_path: Path,
    include_classes: bool,
    include_nested: bool,
    min_lines: int,
    min_tokens: int,
    shingle_size: int,
    num_perm: int,
    coeffs: list[tuple[int, int]],
    normalize_literals: bool,
) -> list[CodeBlock]:
    try:
        src = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    try:
        tree = ast.parse(src, filename=str(file_path))
    except SyntaxError:
        return []
    extractor = BlockExtractor(
        path=_norm_path(file_path),
        source=src,
        include_classes=include_classes,
        include_nested=include_nested,
        min_lines=min_lines,
        min_tokens=min_tokens,
        shingle_size=shingle_size,
        num_perm=num_perm,
        hash_coeffs=coeffs,
        normalize_literals=normalize_literals,
    )
    extractor.visit(tree)
    return extractor.blocks


def _assign_ids(blocks: list[CodeBlock]) -> list[CodeBlock]:
    with_ids: list[CodeBlock] = []
    for idx, block in enumerate(blocks):
        with_ids.append(
            CodeBlock(
                block_id=idx,
                path=block.path,
                qualname=block.qualname,
                node_type=block.node_type,
                start_line=block.start_line,
                end_line=block.end_line,
                line_count=block.line_count,
                normalized_source=block.normalized_source,
                tokens=block.tokens,
                shingles=block.shingles,
                signature=block.signature,
                canonical_names=block.canonical_names,
            )
        )
    return with_ids


def _build_lsh_index(
    blocks: list[CodeBlock], bands: int, max_bucket_size: int
) -> tuple[dict[tuple[int, int], list[int]], set[tuple[int, int]]]:
    buckets: dict[tuple[int, int], list[int]] = defaultdict(list)
    for block in blocks:
        for key in _band_keys(block.signature, bands):
            buckets[key].append(block.block_id)

    candidates: set[tuple[int, int]] = set()
    for idxs in buckets.values():
        if len(idxs) <= 1:
            continue
        unique = sorted(set(idxs))
        if len(unique) > max_bucket_size:
            continue
        for i, j in combinations(unique, 2):
            candidates.add((i, j))
    return buckets, candidates


def _parse_query(query: str) -> tuple[str, int]:
    if ":" not in query:
        raise ValueError("query must be FILE:LINE")
    file_part, line_part = query.rsplit(":", 1)
    try:
        line = int(line_part)
    except ValueError as exc:
        raise ValueError("query line must be an integer") from exc
    return _norm_path(Path(file_part)), line


def _find_anchor(blocks: list[CodeBlock], query_file: str, query_line: int) -> CodeBlock | None:
    best: CodeBlock | None = None
    for block in blocks:
        if block.path != query_file:
            continue
        if block.start_line <= query_line <= block.end_line:
            if best is None or block.line_count < best.line_count:
                best = block
    return best


def resolve_search_args(args: argparse.Namespace) -> argparse.Namespace:
    sensitivity = getattr(args, "sensitivity", None) or "medium"
    if sensitivity not in SENSITIVITY_PRESETS:
        choices = ", ".join(sorted(SENSITIVITY_PRESETS))
        raise ValueError(f"--sensitivity must be one of: {choices}")
    preset = SENSITIVITY_PRESETS[sensitivity]
    args.sensitivity = sensitivity
    if getattr(args, "min_lines", None) is None:
        args.min_lines = preset["min_lines"]
    if getattr(args, "min_tokens", None) is None:
        args.min_tokens = preset["min_tokens"]
    if getattr(args, "exclude_functions", None) is None:
        args.exclude_functions = []
    if isinstance(args.exclude_functions, str):
        args.exclude_functions = [args.exclude_functions]
    return args


def _normalize_ignore_specs(raw_specs: list[str]) -> list[str]:
    specs: list[str] = []
    for raw in raw_specs:
        for part in str(raw).split(","):
            item = part.strip()
            if item:
                specs.append(item)
    return specs


def _compile_ignore_specs(raw_specs: list[str]) -> tuple[set[str], list[str], list[re.Pattern[str]], list[str]]:
    exact: set[str] = set()
    globs: list[str] = []
    regexes: list[re.Pattern[str]] = []
    specs = _normalize_ignore_specs(raw_specs)
    for spec in specs:
        if spec.startswith("re:"):
            pattern = spec[3:].strip()
            if not pattern:
                raise ValueError("empty regex in ignore rule; use re:<pattern>")
            try:
                regexes.append(re.compile(pattern))
            except re.error as exc:
                raise ValueError(f"invalid ignore regex '{spec}': {exc}") from exc
            continue
        if any(ch in spec for ch in "*?["):
            globs.append(spec)
            continue
        exact.add(spec)
    return exact, globs, regexes, specs


def _is_ignored_function(
    block: CodeBlock, exact: set[str], globs: list[str], regexes: list[re.Pattern[str]]
) -> bool:
    if block.node_type not in FUNCTION_NODE_TYPES:
        return False
    leaf = block.qualname.rsplit(".", 1)[-1]
    candidates = (block.qualname, leaf)
    if any(name in exact for name in candidates):
        return True
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in globs for name in candidates):
        return True
    return any(regex.search(name) for regex in regexes for name in candidates)


def _block_payload(block: CodeBlock) -> dict[str, Any]:
    return {
        "path": block.path,
        "qualname": block.qualname,
        "node_type": block.node_type,
        "start_line": block.start_line,
        "end_line": block.end_line,
        "line_count": block.line_count,
    }


def _build_clusters(matches: list[Match]) -> list[dict[str, Any]]:
    if not matches:
        return []
    adjacency: dict[int, set[int]] = defaultdict(set)
    blocks_by_id: dict[int, CodeBlock] = {}
    edges: dict[tuple[int, int], Match] = {}
    for match in matches:
        left_id = match.left.block_id
        right_id = match.right.block_id
        key = (left_id, right_id) if left_id < right_id else (right_id, left_id)
        edges[key] = match
        adjacency[left_id].add(right_id)
        adjacency[right_id].add(left_id)
        blocks_by_id[left_id] = match.left
        blocks_by_id[right_id] = match.right

    components: list[list[int]] = []
    visited: set[int] = set()
    for node_id in sorted(adjacency):
        if node_id in visited:
            continue
        stack = [node_id]
        visited.add(node_id)
        component: list[int] = []
        while stack:
            current = stack.pop()
            component.append(current)
            for neighbor in sorted(adjacency[current]):
                if neighbor not in visited:
                    visited.add(neighbor)
                    stack.append(neighbor)
        components.append(sorted(component))

    clusters: list[dict[str, Any]] = []
    for component in components:
        member_set = set(component)
        member_blocks = [blocks_by_id[i] for i in component]
        member_blocks.sort(key=lambda b: (b.path, b.start_line, b.qualname))
        component_matches = [
            match for (i, j), match in edges.items() if i in member_set and j in member_set
        ]
        component_matches.sort(key=lambda m: (m.score, m.jaccard, m.sequence_ratio), reverse=True)
        scores = [m.score for m in component_matches]
        directories = sorted({str(Path(block.path).parent) for block in member_blocks})
        cluster: dict[str, Any] = {
            "cluster_id": 0,
            "member_count": len(member_blocks),
            "match_count": len(component_matches),
            "avg_score": round(sum(scores) / len(scores), 6) if scores else 0.0,
            "max_score": round(max(scores), 6) if scores else 0.0,
            "directories": directories,
            "members": [_block_payload(block) for block in member_blocks],
            "pairs": [
                {
                    "score": round(match.score, 6),
                    "left": {
                        "path": match.left.path,
                        "qualname": match.left.qualname,
                        "start_line": match.left.start_line,
                        "end_line": match.left.end_line,
                    },
                    "right": {
                        "path": match.right.path,
                        "qualname": match.right.qualname,
                        "start_line": match.right.start_line,
                        "end_line": match.right.end_line,
                    },
                }
                for match in component_matches
            ],
        }
        clusters.append(cluster)
    clusters.sort(
        key=lambda c: (c["member_count"], c["match_count"], c["avg_score"], c["max_score"]),
        reverse=True,
    )
    for idx, cluster in enumerate(clusters, start=1):
        cluster["cluster_id"] = idx
    return clusters


def run_search(args: argparse.Namespace) -> dict[str, Any]:
    resolve_search_args(args)
    includes = tuple(args.include)
    excludes = tuple(args.exclude)
    ignored_exact, ignored_globs, ignored_regexes, ignored_specs = _compile_ignore_specs(
        list(args.exclude_functions)
    )
    coeffs = _compile_hash_coefficients(args.num_perm)
    files = _iter_python_files(args.paths, includes, excludes)

    all_blocks: list[CodeBlock] = []
    for path in files:
        all_blocks.extend(
            _extract_blocks_from_file(
                file_path=path,
                include_classes=args.include_classes,
                include_nested=args.include_nested,
                min_lines=args.min_lines,
                min_tokens=args.min_tokens,
                shingle_size=args.shingle_size,
                num_perm=args.num_perm,
                coeffs=coeffs,
                normalize_literals=not args.no_literal_normalization,
            )
        )
    pre_filter_blocks = _assign_ids(all_blocks)
    ignored_block_count = 0
    if ignored_specs:
        kept_blocks = [
            block
            for block in pre_filter_blocks
            if not _is_ignored_function(block, ignored_exact, ignored_globs, ignored_regexes)
        ]
        ignored_block_count = len(pre_filter_blocks) - len(kept_blocks)
        blocks = _assign_ids(kept_blocks)
    else:
        blocks = pre_filter_blocks
    if not blocks:
        return {
            "summary": {
                "files_scanned": len(files),
                "blocks_indexed": 0,
                "candidate_pairs": 0,
                "matches_found": 0,
                "clusters_found": 0,
                "threshold": args.threshold,
                "query": args.query,
                "sensitivity": args.sensitivity,
                "min_lines": args.min_lines,
                "min_tokens": args.min_tokens,
                "ignore_rules": ignored_specs,
                "blocks_skipped_by_ignore_rules": ignored_block_count,
            },
            "matches": [],
            "clusters": [],
        }

    buckets, candidate_pairs = _build_lsh_index(
        blocks=blocks, bands=args.bands, max_bucket_size=args.max_bucket_size
    )

    matches: list[Match] = []
    candidates_considered = 0
    if args.query:
        query_file, query_line = _parse_query(args.query)
        anchor = _find_anchor(blocks, query_file, query_line)
        if anchor is None:
            raise ValueError(f"no code block found for query {args.query}")
        candidate_ids: set[int] = set()
        for key in _band_keys(anchor.signature, args.bands):
            for idx in buckets.get(key, []):
                if idx != anchor.block_id:
                    candidate_ids.add(idx)
        for idx in sorted(candidate_ids):
            other = blocks[idx]
            candidates_considered += 1
            match = _compute_match(anchor, other)
            if match.score >= args.threshold:
                matches.append(match)
    else:
        for i, j in sorted(candidate_pairs):
            left = blocks[i]
            right = blocks[j]
            candidates_considered += 1
            ratio = min(left.line_count, right.line_count) / max(left.line_count, right.line_count)
            if ratio < args.min_line_ratio:
                continue
            match = _compute_match(left, right)
            if match.score >= args.threshold:
                matches.append(match)

    matches.sort(key=lambda m: (m.score, m.jaccard, m.sequence_ratio), reverse=True)
    if args.top > 0:
        matches = matches[: args.top]
    clusters = _build_clusters(matches) if args.cluster else []

    result = {
        "summary": {
            "files_scanned": len(files),
            "blocks_indexed": len(blocks),
            "candidate_pairs": len(candidate_pairs),
            "candidate_pairs_considered": candidates_considered,
            "matches_found": len(matches),
            "clusters_found": len(clusters),
            "threshold": args.threshold,
            "query": args.query,
            "sensitivity": args.sensitivity,
            "min_lines": args.min_lines,
            "min_tokens": args.min_tokens,
            "ignore_rules": ignored_specs,
            "blocks_skipped_by_ignore_rules": ignored_block_count,
            "cluster_mode": bool(args.cluster),
            "notes": [
                "Identifiers are normalized for local variables/arguments, so variable renames still match.",
                "Scoring combines shingle Jaccard, normalized-source sequence ratio, and token overlap.",
                "Use --query FILE:LINE to focus refactoring search around one specific block.",
                "Ignore rules accept exact names, glob patterns, and regex via re:<pattern>.",
            ],
        },
        "matches": [
            m.to_dict(include_snippets=args.with_snippets, snippet_max_chars=args.snippet_max_chars)
            for m in matches
        ],
        "clusters": clusters,
    }
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="duphunter-near-dup",
        description=(
            "Find near-duplicate Python code blocks for refactoring, including matches "
            "that only differ by local variable names."
        ),
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Files/directories to scan")
    parser.add_argument("--include", action="append", default=["*.py"], help="Include glob pattern")
    parser.add_argument(
        "--exclude",
        action="append",
        default=list(DEFAULT_EXCLUDES),
        help="Exclude glob pattern",
    )
    parser.add_argument("--include-classes", action="store_true", help="Include class blocks")
    parser.add_argument(
        "--include-nested",
        action="store_true",
        help="Include nested functions (functions inside functions)",
    )
    parser.add_argument(
        "--exclude-functions",
        "--ignore-list",
        dest="exclude_functions",
        action="append",
        default=[],
        help=(
            "Comma-separated function filters to skip from matching. Supports exact names, "
            "glob patterns, and regex via re:<pattern>."
        ),
    )
    parser.add_argument(
        "--sensitivity",
        choices=sorted(SENSITIVITY_PRESETS),
        default="medium",
        help="Preset for block-size filtering (low=strict, medium=balanced, high=more matches)",
    )
    parser.add_argument(
        "--min-lines",
        type=int,
        default=None,
        help="Minimum block size in lines (defaults by --sensitivity)",
    )
    parser.add_argument(
        "--min-tokens",
        type=int,
        default=None,
        help="Minimum normalized token count (defaults by --sensitivity)",
    )
    parser.add_argument("--shingle-size", type=int, default=6, help="Token shingle size")
    parser.add_argument("--num-perm", type=int, default=64, help="Number of MinHash permutations")
    parser.add_argument("--bands", type=int, default=16, help="Number of LSH bands")
    parser.add_argument(
        "--max-bucket-size",
        type=int,
        default=120,
        help="Skip overly generic LSH buckets above this size",
    )
    parser.add_argument("--threshold", type=float, default=0.76, help="Minimum final similarity score")
    parser.add_argument(
        "--min-line-ratio",
        type=float,
        default=0.45,
        help="Minimum smaller/larger line-count ratio for candidate pairs",
    )
    parser.add_argument("--top", type=int, default=200, help="Maximum number of matches to return")
    parser.add_argument(
        "--query",
        type=str,
        default=None,
        help="Focus on one block via FILE:LINE and return its near duplicates",
    )
    parser.add_argument(
        "--cluster",
        action="store_true",
        help="Group related pairwise matches into connected clusters",
    )
    parser.add_argument(
        "--no-literal-normalization",
        action="store_true",
        help="Keep string/number literals as-is instead of canonical placeholders",
    )
    parser.add_argument("--with-snippets", action="store_true", help="Include normalized code snippets")
    parser.add_argument("--snippet-max-chars", type=int, default=500, help="Max chars per snippet")
    parser.add_argument("--output", choices=("json", "text"), default="json", help="Output format")
    parser.add_argument("--json-indent", type=int, default=2, help="JSON indentation")
    parser.add_argument(
        "--mcp-server",
        action="store_true",
        help="Run as an MCP stdio server exposing this search as a tool",
    )
    return parser


def validate_search_args(args: argparse.Namespace) -> None:
    resolve_search_args(args)
    if args.num_perm <= 0:
        raise ValueError("--num-perm must be > 0")
    if args.bands <= 0:
        raise ValueError("--bands must be > 0")
    if args.num_perm % args.bands != 0:
        raise ValueError("--num-perm must be divisible by --bands")
    if args.shingle_size <= 0:
        raise ValueError("--shingle-size must be > 0")
    if args.min_lines <= 0:
        raise ValueError("--min-lines must be > 0")
    if args.min_tokens <= 0:
        raise ValueError("--min-tokens must be > 0")
    if args.top < 0:
        raise ValueError("--top must be >= 0")
    if not (0.0 <= args.min_line_ratio <= 1.0):
        raise ValueError("--min-line-ratio must be between 0.0 and 1.0")
    if not (0.0 <= args.threshold <= 1.0):
        raise ValueError("--threshold must be between 0.0 and 1.0")


def _render_text(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        (
            "files_scanned={files_scanned} blocks_indexed={blocks_indexed} "
            "candidate_pairs={candidate_pairs} matches_found={matches_found} "
            "clusters_found={clusters_found} threshold={threshold} sensitivity={sensitivity}"
        ).format(**summary)
    ]
    ignore_rules = summary.get("ignore_rules") or []
    if ignore_rules:
        lines.append(
            f"ignore_rules={','.join(ignore_rules)} skipped_blocks={summary.get('blocks_skipped_by_ignore_rules', 0)}"
        )
    for cluster in result.get("clusters", []):
        lines.append(
            (
                f"[cluster {cluster['cluster_id']}] members={cluster['member_count']} "
                f"pairs={cluster['match_count']} avg_score={cluster['avg_score']:.4f} "
                f"max_score={cluster['max_score']:.4f}"
            )
        )
        for member in cluster["members"]:
            lines.append(
                f"    * {member['path']}:{member['start_line']}-{member['end_line']} {member['qualname']}"
            )
    for idx, match in enumerate(result["matches"], start=1):
        left = match["left"]
        right = match["right"]
        lines.append(
            (
                f"[{idx}] score={match['score']:.4f} jaccard={match['jaccard']:.4f} "
                f"seq={match['sequence_ratio']:.4f} overlap={match['token_overlap']:.4f}"
            )
        )
        lines.append(
            f"    L {left['path']}:{left['start_line']}-{left['end_line']} {left['qualname']}"
        )
        lines.append(
            f"    R {right['path']}:{right['start_line']}-{right['end_line']} {right['qualname']}"
        )
        if match["identifier_renames"]:
            rename_pairs = ", ".join(
                f"{src}->{dst}" for src, dst in sorted(match["identifier_renames"].items())
            )
            lines.append(f"    renames: {rename_pairs}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        validate_search_args(args)
    except ValueError as exc:
        parser.error(str(exc))
    if args.mcp_server:
        from .mcp_server import run_stdio_server

        return run_stdio_server(args)
    try:
        result = run_search(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.output == "json":
        print(json.dumps(result, indent=args.json_indent, ensure_ascii=True))
    else:
        print(_render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
