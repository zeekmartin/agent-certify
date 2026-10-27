# Contributing to agent-certify

## Quick start

```bash
git clone https://github.com/zeekmartin/agent-certify.git
cd agent-certify
python -m venv .venv
source .venv/bin/activate  # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest tests/ -v
ruff check src/ tests/
```

## Rules

- Open an issue before submitting a PR
- All tests must pass
- Ruff must report no errors
- No new dependencies without discussion
- Keep it simple — zero heavy dependencies by design

## License

By contributing you agree your contributions are licensed under Apache 2.0.
