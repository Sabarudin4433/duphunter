from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from typing import Any

from .near_dup_search import (
    DEFAULT_EXCLUDES,
    SENSITIVITY_PRESETS,
    resolve_search_args,
    run_search,
    validate_search_args,
)

SERVER_NAME = "duphunter-near-dup"
SERVER_VERSION = "0.1.0"
TOOL_NAME = "search_near_duplicates"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

TOOL_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Files/directories to scan",
        },
        "include": {"type": "array", "items": {"type": "string"}},
        "exclude": {"type": "array", "items": {"type": "string"}},
        "include_classes": {"type": "boolean"},
        "include_nested": {"type": "boolean"},
        "exclude_functions": {"type": "array", "items": {"type": "string"}},
        "ignore_list": {"type": "array", "items": {"type": "string"}},
        "sensitivity": {"type": "string", "enum": sorted(SENSITIVITY_PRESETS)},
        "min_lines": {"type": "integer", "minimum": 1},
        "min_tokens": {"type": "integer", "minimum": 1},
        "shingle_size": {"type": "integer", "minimum": 1},
        "num_perm": {"type": "integer", "minimum": 1},
        "bands": {"type": "integer", "minimum": 1},
        "max_bucket_size": {"type": "integer", "minimum": 2},
        "threshold": {"type": "number"},
        "min_line_ratio": {"type": "number"},
        "top": {"type": "integer", "minimum": 1},
        "query": {"type": "string"},
        "cluster": {"type": "boolean"},
        "no_literal_normalization": {"type": "boolean"},
        "with_snippets": {"type": "boolean"},
        "snippet_max_chars": {"type": "integer", "minimum": 20},
    },
}

_ALLOWED_ARGS = frozenset(TOOL_INPUT_SCHEMA["properties"])


def _read_message() -> dict[str, Any] | None:
    # Peek at the first byte to detect framing mode.
    first = sys.stdin.buffer.peek(1)[:1]
    if not first:
        # EOF before any data.
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        first = line[:1]
    else:
        line = None

    if first == b"{":
        # Newline-delimited JSON (no Content-Length header).
        if line is None:
            line = sys.stdin.buffer.readline()
        if not line:
            return None
        return json.loads(line.decode("utf-8"))

    # Content-Length framed messages.
    headers: dict[str, str] = {}
    if line is not None:
        decoded = line.decode("utf-8", errors="replace").strip()
        if ":" in decoded:
            name, value = decoded.split(":", 1)
            headers[name.lower().strip()] = value.strip()
    while True:
        hline = sys.stdin.buffer.readline()
        if not hline:
            return None
        if hline in (b"\r\n", b"\n"):
            break
        decoded = hline.decode("utf-8", errors="replace").strip()
        if ":" not in decoded:
            continue
        name, value = decoded.split(":", 1)
        headers[name.lower().strip()] = value.strip()
    content_length = int(headers.get("content-length", "0"))
    if content_length <= 0:
        return None
    body = sys.stdin.buffer.read(content_length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def _write_message(payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    # Write both Content-Length framed and newline-terminated for compatibility.
    header = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()


def _jsonrpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _normalize_tool_args(base_args: argparse.Namespace, arguments: dict[str, Any]) -> argparse.Namespace:
    unknown = sorted(set(arguments) - _ALLOWED_ARGS)
    if unknown:
        raise ValueError(f"unsupported arguments: {', '.join(unknown)}")
    args = argparse.Namespace(**deepcopy(vars(base_args)))
    alias_ignore = arguments.get("ignore_list")
    alias_exclude = arguments.get("exclude_functions")
    if alias_ignore is not None:
        merged: list[str] = []
        if isinstance(alias_exclude, list):
            merged.extend(str(v) for v in alias_exclude)
        elif alias_exclude is not None:
            merged.append(str(alias_exclude))
        if isinstance(alias_ignore, list):
            merged.extend(str(v) for v in alias_ignore)
        else:
            merged.append(str(alias_ignore))
        arguments = dict(arguments)
        arguments["exclude_functions"] = merged
    for key, value in arguments.items():
        if key == "ignore_list":
            continue
        setattr(args, key, value)
    if isinstance(args.paths, str):
        args.paths = [args.paths]
    if isinstance(args.include, str):
        args.include = [args.include]
    if isinstance(args.exclude, str):
        args.exclude = [args.exclude]
    if isinstance(args.exclude_functions, str):
        args.exclude_functions = [args.exclude_functions]
    resolve_search_args(args)
    args.output = "json"
    args.json_indent = 2
    args.mcp_server = False
    validate_search_args(args)
    return args


def _handle_tools_call(params: dict[str, Any], base_args: argparse.Namespace) -> dict[str, Any]:
    name = params.get("name")
    if name != TOOL_NAME:
        raise ValueError(f"unknown tool: {name}")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    args = _normalize_tool_args(base_args, arguments)
    result = run_search(args)
    return {
        "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=True)}],
        "structuredContent": result,
    }


def run_stdio_server(base_args: argparse.Namespace) -> int:
    protocol_version = DEFAULT_PROTOCOL_VERSION
    while True:
        message = _read_message()
        if message is None:
            return 0
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})
        if not method:
            if request_id is not None:
                _write_message(_jsonrpc_error(request_id, -32600, "invalid request"))
            continue

        if request_id is None:
            continue

        if method == "initialize":
            req_protocol = params.get("protocolVersion")
            if isinstance(req_protocol, str) and req_protocol:
                protocol_version = req_protocol
            result = {
                "protocolVersion": protocol_version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }
            _write_message(_jsonrpc_result(request_id, result))
            continue
        if method == "ping":
            _write_message(_jsonrpc_result(request_id, {}))
            continue
        if method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": TOOL_NAME,
                        "description": (
                            "Find near-duplicate Python code blocks for refactoring, including "
                            "matches that only differ by local variable names."
                        ),
                        "inputSchema": TOOL_INPUT_SCHEMA,
                    }
                ]
            }
            _write_message(_jsonrpc_result(request_id, result))
            continue
        if method == "tools/call":
            try:
                tool_result = _handle_tools_call(params if isinstance(params, dict) else {}, base_args)
                _write_message(_jsonrpc_result(request_id, tool_result))
            except ValueError as exc:
                _write_message(
                    _jsonrpc_result(
                        request_id,
                        {"content": [{"type": "text", "text": str(exc)}], "isError": True},
                    )
                )
            continue

        _write_message(_jsonrpc_error(request_id, -32601, f"method not found: {method}"))


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="duphunter-mcp",
        description="Run DupHunter near-duplicate search as an MCP stdio server",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Default paths to scan")
    parser.add_argument("--include", action="append", default=["*.py"], help="Default include glob")
    parser.add_argument("--exclude", action="append", default=list(DEFAULT_EXCLUDES), help="Default exclude glob")
    parser.add_argument("--include-classes", action="store_true", help="Include class blocks by default")
    parser.add_argument("--include-nested", action="store_true", help="Include nested functions by default")
    parser.add_argument(
        "--exclude-functions",
        "--ignore-list",
        dest="exclude_functions",
        action="append",
        default=[],
    )
    parser.add_argument("--sensitivity", choices=sorted(SENSITIVITY_PRESETS), default="high")
    parser.add_argument("--min-lines", type=int, default=None)
    parser.add_argument("--min-tokens", type=int, default=None)
    parser.add_argument("--shingle-size", type=int, default=6)
    parser.add_argument("--num-perm", type=int, default=64)
    parser.add_argument("--bands", type=int, default=16)
    parser.add_argument("--max-bucket-size", type=int, default=120)
    parser.add_argument("--threshold", type=float, default=0.76)
    parser.add_argument("--min-line-ratio", type=float, default=0.45)
    parser.add_argument("--top", type=int, default=200)
    parser.add_argument("--query", type=str, default=None)
    parser.add_argument("--cluster", action="store_true")
    parser.add_argument("--no-literal-normalization", action="store_true")
    parser.add_argument("--with-snippets", action="store_true")
    parser.add_argument("--snippet-max-chars", type=int, default=500)
    args = parser.parse_args()
    resolve_search_args(args)
    args.output = "json"
    args.json_indent = 2
    args.mcp_server = False
    validate_search_args(args)
    return run_stdio_server(args)


if __name__ == "__main__":
    raise SystemExit(main())
