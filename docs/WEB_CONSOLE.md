# NEXUS IDS web console

The NEXUS IDS web console is an optional local interface over the existing packet-analysis and rule-based IDS engine. It complements the command-line interface; it does not replace it.

## Start on Windows PowerShell

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[web,dev]"
python -m uvicorn sentinel.web:app --host 127.0.0.1 --port 8000
```

## Start on Linux / Kali Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[web,dev]"
python -m uvicorn sentinel.web:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. API documentation is at http://127.0.0.1:8000/api/docs.

## Features

- Upload PCAP and PCAPNG captures up to 25 MiB.
- Analyze uploads with the configured default NEXUS IDS rules.
- Display alert totals, severity breakdowns, and recent detection events.
- Persist alert metadata in local SQLite storage.
- Filter alert history by severity and export up to 500 recent alerts to CSV.
- Process uploaded capture bytes in memory; the web endpoint does not save the uploaded capture file.

## Storage and safety

By default, alert metadata is stored at `~/.nexus-ids/alerts.sqlite3`. Set `NEXUS_IDS_DB` to choose another path. The legacy `SENTINEL_DB` variable is still accepted for compatibility. The documented server command binds to `127.0.0.1`. The console has no user authentication and must not be exposed directly to the public internet. Only analyze captures you are authorized to inspect; packet metadata can contain sensitive information.

The web console supports offline capture analysis. Live capture remains available through the CLI on supported platforms; the dashboard does not claim to start or stop live capture.
