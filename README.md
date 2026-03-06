# DupHunter

**AST-driven near-duplicate code detector for Python.** Finds copy-paste clones even when variables are renamed. Built for AI-assisted refactoring workflows.

```
$ duphunter-near-dup src/ --output text --threshold 0.76

src/api/users.py:45  get_user_by_id
src/api/orders.py:89 get_order_by_id
  similarity: 0.91 | 12 lines each | 3 AST diffs
```

## Why?

Linters catch style issues. Type checkers catch type errors. **DupHunter catches structural duplication** — the kind that leads to bugs when you fix something in one copy but forget the other.

- **AST normalization**: Renames local variables to positional placeholders, so `get_user_by_id` and `get_order_by_id` match even with different parameter names
- **MinHash + LSH indexing**: Scales to large codebases without O(N^2) pairwise comparison
- **Literal normalization**: Finds "same logic, different data" clones (strings, numbers normalized)
- **Cluster output**: Groups transitive duplicates — if A~B and B~C, reports {A, B, C}
- **MCP server**: AI assistants can search for duplicates directly

## Install

```bash
# Global install (recommended)
pipx install duphunter

# Or with pip
pip install duphunter
```

## Quick Start

### CLI

```bash
# Scan entire project
duphunter-near-dup .

# Focused search: "what's similar to the function at line 120?"
duphunter-near-dup . --query src/app.py:120 --top 20

# Human-readable output
duphunter-near-dup . --output text

# Cluster transitive duplicates
duphunter-near-dup . --cluster --output text

# Adjust sensitivity
duphunter-near-dup . --threshold 0.72          # more results, looser matching
duphunter-near-dup . --sensitivity high        # catch small 4-5 line helpers

# Ignore known patterns
duphunter-near-dup . --exclude-functions "test_*,setup_*"
duphunter-near-dup . --exclude-functions "re:^get_.*_by_.*$"
```

### MCP Server (for AI assistants)

Add to `~/.claude.json` or `.mcp.json`:

```json
{
  "mcpServers": {
    "duphunter": {
      "command": "duphunter-mcp"
    }
  }
}
```

**MCP tool**: `search_near_duplicates` — accepts the same options as CLI flags (as JSON fields), returns structured match payload. Default sensitivity is `high` in MCP mode.

## How It Works

1. **Parse**: Python AST extracts all function and class bodies
2. **Normalize**: Local identifiers → positional placeholders (`arg0`, `local1`), literals → type tokens
3. **Fingerprint**: Normalized AST tokens → MinHash signatures (128 permutations)
4. **Index**: LSH bands for fast candidate retrieval
5. **Compare**: Candidate pairs scored by Jaccard similarity on AST token shingles
6. **Report**: Pairs above threshold, optionally clustered by transitivity

## Ignore Rules

Filter out known wrappers, test helpers, or generated code:

| Format | Example | Matches |
|--------|---------|---------|
| Exact name | `approve_suggestion` | Only that function |
| Glob pattern | `get_*_by_*` | `get_user_by_id`, `get_order_by_name`, ... |
| Regex | `re:^test_.*_integration$` | `test_api_integration`, `test_db_integration`, ... |

Multiple rules: comma-separated or repeated flags.

## Recommended Defaults

| Use case | Command |
|----------|---------|
| General scan | `duphunter-near-dup . --threshold 0.76` |
| Refactoring prep | `duphunter-near-dup . --query FILE:LINE --top 20` |
| Catch small helpers | `duphunter-near-dup . --sensitivity high` |
| CI integration | `duphunter-near-dup . --threshold 0.85 --output json` |

## Requirements

- Python 3.10+
- No external dependencies (stdlib only — uses `ast`, `hashlib`, `collections`)

## License

MIT
