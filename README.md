# lx5-header-scan

Educational tool to inspect common HTTP security headers.

## What it does
- Fetches a URL (optionally follows redirects)
- Reports which common security headers are present/missing

## Responsible use
Only scan systems you own or have explicit permission to test.

## Install
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
