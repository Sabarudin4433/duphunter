# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DupHunter is an AST-driven near-duplicate detector for Python code blocks, designed for coding-agent refactoring workflows. It normalizes local identifiers and uses MinHash + LSH for efficient similarity search, returning machine-friendly JSON output.

## Commands

```bash
# Run the tool
python -m duphunter .
python -m duphunter . --query src/app.py:120 --top 20
python -m duphunter . --cluster --output text

# Run as MCP stdio server
python -m duphunter --mcp-server
duphunter-mcp

# Install in development mode
pip install -e .
```

No test suite or linter is configured yet.

## Architecture

The entire codebase lives in the `duphunter/` package with 4 meaningful modules:

- **`near_dup_search.py`** — Core engine and CLI entry point (`main()`). Contains everything: AST parsing, identifier normalization (`LocalNameCanonicalizer`), block extraction (`BlockExtractor`), MinHash/LSH indexing, match scoring, cluster building, arg parsing (`build_arg_parser`), and text/JSON rendering. The `run_search(args)` function is the main programmatic API.
- **`mcp_server.py`** — MCP stdio server wrapping `run_search`. Implements JSON-RPC over stdin/stdout with `Content-Length` framing. Exposes a single tool `search_near_duplicates`. MCP defaults to `--sensitivity high`.
- **`cli.py`** / **`__main__.py`** — Thin wrappers that call `near_dup_search.main()`.

### Key data flow

1. Walk filesystem → parse Python files into ASTs
2. `BlockExtractor` visits function/class nodes, `LocalNameCanonicalizer` normalizes local names and literals
3. Normalized source is tokenized → shingled → MinHash signatures computed
4. LSH banding groups similar signatures into candidate pairs
5. Candidates are scored: `0.65 * jaccard + 0.25 * sequence_ratio + 0.10 * token_overlap`
6. Optional `--cluster` groups matches into connected components

### Entry points (pyproject.toml)

- `duphunter-near-dup` → `duphunter.cli:main`
- `duphunter-mcp` → `duphunter.mcp_server:main`

## Key conventions

- No external dependencies beyond the Python 3.10+ stdlib
- All hashing uses `blake2b` with 8-byte digests for stable 64-bit values
- Sensitivity presets (`low`/`medium`/`high`) control `min_lines` and `min_tokens` thresholds
- Ignore rules support three formats: exact name, glob pattern, `re:<regex>`
