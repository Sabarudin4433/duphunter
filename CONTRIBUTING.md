# Contributing to DupHunter

Thanks for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/faxik/duphunter.git
cd duphunter
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Project Structure

```
duphunter/
  near_dup_search.py  — Core engine: AST parsing, normalization, MinHash, LSH, matching
  cli.py              — CLI interface (argparse)
  mcp_server.py       — MCP server (FastMCP, single tool)
  __main__.py         — Entry point for python -m duphunter
```

## Design Principles

- **Zero dependencies**: stdlib only (ast, hashlib, collections). No numpy, no scipy.
- **AI-first output**: JSON by default. Text output is optional.
- **Single-file engine**: All core logic in `near_dup_search.py`. Easy to understand and modify.
- **Normalization is key**: The quality of duplicate detection depends on how well we normalize AST tokens. Improvements here have the highest impact.

## Adding Features

1. Core algorithm changes go in `near_dup_search.py`
2. New CLI flags go in `cli.py`
3. Mirror new options in `mcp_server.py` for MCP clients

## Code Style

- Type hints on public functions
- No external dependencies
- Keep `near_dup_search.py` self-contained
