# NEXUS IDS — Network Threat Detection & Analysis System

<img width="1440" height="1000" alt="01-nexus-ids-desktop" src="https://github.com/user-attachments/assets/9258a521-7a7d-4153-b13c-bb2f3876ba46" />

NEXUS IDS is a Python-based network packet analysis and rule-driven intrusion detection project. The local web console uses a restrained steel-blue and slate interface designed for practical security operations rather than decorative effects. It combines a command-line analyzer with an optional local web console for offline PCAP/PCAPNG investigation, alert review, and CSV reporting.

> **Attribution and license:** The packet parser, flow engine, filter language, IDS engine, original CLI, rules, and original test suite are based on the upstream MIT-licensed project by Kaan Dinç: [kaan0d/sentinel](https://github.com/kaan0d/sentinel). The upstream copyright and MIT license are retained in [`LICENSE.md`](LICENSE.md). This repository adds the web console, its API, persistence layer, tests, and updated documentation. Review the source and commit history before describing individual components as independently authored.

## Highlights

### Packet analysis
- Read classic PCAP and PCAPNG capture files.
- Decode Ethernet (including VLAN), ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP/1.x, and TLS ClientHello fields.
- Inspect bidirectional network flows and reassembled TCP streams.
- Filter packets with a BPF-like expression language.

### Intrusion detection
- Apply configurable, rule-based detectors for port scans, SYN floods, ARP spoofing, DNS tunnelling indicators, SSH brute-force indicators, and ICMP tunnelling.
- Review severity, detector, source/destination, rule, and supporting evidence for generated alerts.
- Load TOML rules from the included defaults, a rule file, or a rules directory.

### Local SOC-style web console
- Upload PCAP/PCAPNG files up to 25 MiB for offline analysis.
- View alert totals and severity breakdowns.
- Filter recent alert history by severity.
- Persist alert metadata in a local SQLite database.
- Export up to 500 recent alerts as CSV.
- Open the interactive API schema at `/api/docs`.

**Scope note:** The web console analyzes uploaded captures offline. Live capture is available through the CLI on supported systems; the dashboard does not start live capture.

## Architecture


                         NEXUS IDS
             NETWORK THREAT DETECTION SYSTEM
                              |
             +----------------+----------------+
             |                                 |
      COMMAND-LINE INTERFACE             WEB CONSOLE
             |                                 |
      +------+-------+                  FastAPI Application
      |      |       |                         |
     READ  FLOWS    IDS / LIVE          Capture Upload API
      |      |       |                         |
      |      |       |                  Input Validation
      |      |       |                         |
      +------+-------+-------------------------+
                     |
              PACKET PROCESSING
                     |
             +-------+--------+
             |                |
       PCAP / PCAPNG      LIVE CAPTURE
       File Processing    (CLI / Supported OS)
             |                |
             +-------+--------+
                     |
              PACKET DECODING
                     |
       +-------------+--------------+
       |             |              |
    Ethernet      Network       Transport
    ARP           IPv4/IPv6      TCP / UDP
                                ICMP
       |             |              |
       +-------------+--------------+
                     |
              PROTOCOL ANALYSIS
                     |
       +-------------+--------------+
       |             |              |
      DNS           HTTP           TLS
       |             |              |
       +-------------+--------------+
                     |
              FLOW PROCESSING
                     |
       +-------------+--------------+
       |                            |
   Flow Analysis              TCP Stream
                              Reassembly
       |                            |
       +-------------+--------------+
                     |
              IDS DETECTION ENGINE
                     |
          +----------+-----------+
          |          |           |
       Detector   Rule Engine   Thresholds
       Modules    (Python)      / Windows
          |          |           |
          +----------+-----------+
                     |
              TOML RULE CONFIGURATION
                     |
              DETECTION EVALUATION
                     |
              ALERT GENERATION
                     |
          +----------+-----------+
          |                      |
    Alert Classification    Detection Evidence
    Severity / Type          Source / Destination
          |                      |
          +----------+-----------+
                     |
              ALERT MANAGEMENT
                     |
          +----------+-----------+
          |                      |
     SQLite Storage        Alert Processing
          |                      |
          +----------+-----------+
                     |
               WEB CONSOLE
                     |
          +----------+-----------+
          |                      |
      Alert Dashboard       Alert History
          |                      |
          +----------+-----------+
                     |
              REPORT GENERATION
                     |
                 CSV EXPORT
                 

## Technology

| Layer | Technology | Purpose |
|---|---|---|
| Core engine | Python 3.12+ | Packet parsing, flow processing and detection |
| Capture formats | PCAP / PCAPNG | Offline packet input |
| Detection | Configurable Python rules + TOML | Rule-driven network threat indicators |
| Web API | FastAPI | Upload, analysis, alert and statistics endpoints |
| Dashboard | HTML, CSS, JavaScript | Local SOC-style investigation interface |
| Persistence | SQLite | Alert metadata and history |
| Testing | pytest | Automated unit and API tests |

The installable distribution is named `nexus-ids`. The established `sentinel` Python module and `python -m sentinel` command are intentionally retained as the internal compatibility namespace so existing imports and scripts continue to work.

## Requirements

- Python 3.12 or newer.
- Windows 10/11, Linux, or Kali Linux.
- Web console dependencies: FastAPI, Uvicorn and `python-multipart` (installed with the `web` extra).
- Live capture: supported platform capture backend and appropriate permissions. Live capture is not required for offline PCAP analysis.

## Installation — Windows PowerShell

Open PowerShell in the extracted project directory:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[web,dev]"
```

If Python 3.13 is not installed, use an installed Python 3.12+ launcher version. If PowerShell blocks virtual-environment activation, invoke `\.venv\Scripts\python.exe` directly instead.

### Start the dashboard

```powershell
python -m uvicorn sentinel.web:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. Interactive API documentation is available at **http://127.0.0.1:8000/api/docs**. Stop the server with `Ctrl+C`.

### Use the command-line interface

```powershell
python -m sentinel --help
python -m sentinel read .\path\to\capture.pcap
python -m sentinel flows .\path\to\capture.pcapng
python -m sentinel ids .\path\to\capture.pcap --format text
```

### Generate a safe synthetic capture

The included generator creates synthetic traffic using documentation/private addresses. It does not transmit packets onto your network.

```powershell
python -m tools.gen_pcap .\nexus-demo.pcap --attacks
python -m sentinel ids .\nexus-demo.pcap --format text
```

Use `python -m tools.gen_pcap --help` to see the generator's available options.

## Installation — Linux / Kali Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[web,dev]"
python -m uvicorn sentinel.web:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. Keep the server bound to localhost unless authentication, TLS, and appropriate network access controls have been configured.

## Detection rules

Default rules are stored in [`rules/default.toml`](rules/default.toml). Supply a TOML file or directory to the CLI:

```bash
python -m sentinel ids capture.pcap --rules rules/ --format json
```

Example rule:

```toml
[[rule]]
id = "ssh-scan"
detector = "port_scan"
severity = "high"
filter = "dst port 22"
distinct_hosts = 5
distinct_ports = 0
window_seconds = 30
```

The rule loader validates rule identifiers, detector names, severity, filters, and detector-specific parameters. See the default rules and `sentinel/ids/rules.py` for supported configuration.

## API reference

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Local service health |
| `POST` | `/api/analyze` | Analyze one uploaded PCAP/PCAPNG capture |
| `GET` | `/api/alerts` | Retrieve recent alerts; optional `severity` and `limit` |
| `GET` | `/api/stats` | Stored alert totals and severity/detector breakdowns |
| `GET` | `/api/export.csv` | Export up to 500 recent alerts |
| `GET` | `/api/docs` | Interactive OpenAPI documentation |

## Data storage and privacy

By default, the dashboard stores alert metadata (not the uploaded capture) in SQLite at `~/.nexus-ids/alerts.sqlite3`. Set `NEXUS_IDS_DB` to select another database path. The legacy `SENTINEL_DB` environment variable remains supported for existing installations. Uploaded capture bytes are processed in memory by the web endpoint and are not retained as uploaded files. Alert metadata and CSV exports may still contain internal IP addresses and investigation details; protect them accordingly.

## Testing and code quality

Install the development dependencies, then run from the repository root:

```powershell
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy
```

The test suite includes packet/protocol parsing, flow processing, IDS detection, CLI, live-capture behavior, and web API tests. Live-capture integration tests may depend on the host operating system, privileges, and available capture libraries. Report the results from the environment in which you actually run the checks; do not assume all platforms behave identically.

## Repository structure

| Path | Responsibility |
|---|---|
| `sentinel/pcap/` | PCAP and PCAPNG readers/writer |
| `sentinel/proto/` | Protocol parsers and packet decoding |
| `sentinel/flow/` | Flow tracking and TCP stream reassembly |
| `sentinel/filter/` | Filter lexer, parser and evaluator |
| `sentinel/ids/` | Detection engine, detectors, rules and alerts |
| `sentinel/live/` | Receive-only live capture backends |
| `sentinel/web.py` | FastAPI upload API and SQLite alert storage |
| `sentinel/web_static/` | Browser dashboard assets |
| `tools/` | Synthetic PCAP generation, benchmarks, fuzzing and comparisons |
| `tests/` | Automated test suite |
| `docs/` | Additional setup and design notes |
| `screenshots/` | Genuine screenshots captured from a local run |

## Limitations and responsible use

- Detection depends on capture visibility, enabled rules, and network vantage point. An alert is an indicator for investigation, not proof of compromise.
- IPv6 extension headers and ICMPv6 are not parsed; IP fragments are not reassembled.
- TCP reassembly is offline and capped at 1 MiB per stream; overlapping data uses first-copy-wins.
- The SSH brute-force detector counts connection attempts, not verified failed logins. DNS tunnel heuristics may produce false positives or miss techniques.
- Windows live capture has platform-specific limitations (IPv4 only and no Ethernet header). Live capture can require Administrator/root privileges.
- The web console has no user authentication and is intended for local development. Do not expose it directly to the public internet.
- Only inspect captures and networks you own or have explicit permission to analyze. Do not generate disruptive traffic on public or shared networks.

## Upstream references and attribution

- Original source project: [kaan0d/sentinel](https://github.com/kaan0d/sentinel)
- Original technical write-ups: [Packet analyzer](https://kaandinc.com/posts/sentinel-packet-analyzer), [next level](https://kaandinc.com/posts/sentinel-next-level), [real traffic](https://kaandinc.com/posts/sentinel-real-world)

## License

MIT. See [`LICENSE.md`](LICENSE.md). The original upstream copyright notice is retained; added web-console code is distributed under the same repository license.

## Development

Install the project and developer tools with `python -m pip install -e ".[web,dev]"`, then run these checks from the repository root:

```
ruff check .
ruff format --check .
mypy
python -m pytest
python -m tools.fuzz --iterations 200000 --seed 1
python -m tools.bench --packets 20000 --repeat 1
```

Live-capture integration tests require the appropriate packet-capture privileges (for example, Linux `CAP_NET_RAW`). Environments without those privileges can still run the offline parser, IDS, CLI, and web API tests.
