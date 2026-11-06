"""NEXUS IDS local web console over the existing packet-analysis and IDS engine."""
from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

from sentinel.ids import Engine, default_rules, to_json
from sentinel.pcap import LINKTYPE_ETHERNET, PcapError, open_reader

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
STATIC_DIR = Path(__file__).with_name("web_static")


def _default_db() -> Path:
    configured = os.environ.get("NEXUS_IDS_DB") or os.environ.get("SENTINEL_DB")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".nexus-ids" / "alerts.sqlite3"


class AlertStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, ts_ns INTEGER NOT NULL, rule TEXT NOT NULL,
                detector TEXT NOT NULL, severity TEXT NOT NULL, src TEXT, dst TEXT,
                message TEXT NOT NULL, evidence TEXT NOT NULL, capture_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_ns DESC)")

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def add_many(self, records: list[dict], capture_name: str) -> None:
        with self.connect() as db:
            db.executemany("""INSERT INTO alerts
                (ts, ts_ns, rule, detector, severity, src, dst, message, evidence, capture_name, created_at)
                VALUES (:ts, :ts_ns, :rule, :detector, :severity, :src, :dst, :message,
                        :evidence, :capture_name, :created_at)""",
                [{**r, "evidence": json.dumps(r["evidence"], sort_keys=True),
                  "capture_name": capture_name, "created_at": datetime.now(UTC).isoformat()}
                 for r in records])

    def list(self, severity: str | None, limit: int) -> list[dict]:
        sql = "SELECT * FROM alerts"
        args: list[object] = []
        if severity:
            sql += " WHERE severity = ?"
            args.append(severity)
        sql += " ORDER BY ts_ns DESC, id DESC LIMIT ?"
        args.append(limit)
        with self.connect() as db:
            rows = db.execute(sql, args).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item["evidence"])
            result.append(item)
        return result

    def stats(self) -> dict:
        with self.connect() as db:
            total = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            by_severity = {r[0]: r[1] for r in db.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity")}
            by_detector = {r[0]: r[1] for r in db.execute(
                "SELECT detector, COUNT(*) FROM alerts GROUP BY detector ORDER BY COUNT(*) DESC")}
        return {"total_alerts": total, "by_severity": by_severity, "by_detector": by_detector}


def create_app(db_path: Path | None = None) -> FastAPI:
    app = FastAPI(title="NEXUS IDS — Network Threat Detection & Analysis System", version="1.0.0", docs_url="/api/docs")
    app.state.store = AlertStore(db_path or _default_db())

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> str:
        return (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "service": "nexus-ids-web", "version": app.version}

    @app.post("/api/analyze")
    async def analyze(file: Annotated[UploadFile, File(...)]) -> dict:
        name = Path(file.filename or "capture.pcap").name
        if not name.lower().endswith((".pcap", ".pcapng")):
            raise HTTPException(415, "Upload a .pcap or .pcapng capture")
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB upload limit")
        if not data:
            raise HTTPException(400, "The uploaded capture is empty")
        engine = Engine(default_rules().rules)
        packets = 0
        protocols: Counter[str] = Counter()
        try:
            reader = open_reader(io.BytesIO(data))
            if reader.linktype != LINKTYPE_ETHERNET:
                raise HTTPException(422, f"Unsupported capture link type: {reader.linktype}; Ethernet is required")
            from sentinel.proto.decode import decode
            for packet in reader:
                layers = decode(packet.data)
                engine.process(packet, layers)
                packets += 1
                for layer in layers:
                    protocols[type(layer).__name__] += 1
            alerts = engine.finish()
        except PcapError as exc:
            raise HTTPException(422, f"Invalid or unsupported capture: {exc}") from exc
        records = []
        for alert in alerts:
            record = json.loads(to_json(alert))
            records.append(record)
        app.state.store.add_many(records, name)
        return {"filename": name, "packets_analyzed": packets, "alerts_found": len(records),
                "protocol_layers": dict(protocols), "alerts": records,
                "message": "Analysis complete. Results are based on the uploaded capture and enabled default rules."}

    @app.get("/api/alerts")
    def alerts(severity: str | None = Query(default=None), limit: int = Query(default=100, ge=1, le=500)) -> dict:
        if severity and severity not in {"low", "medium", "high", "critical"}:
            raise HTTPException(400, "severity must be low, medium, high or critical")
        return {"alerts": app.state.store.list(severity, limit)}

    @app.get("/api/stats")
    def stats() -> dict:
        return app.state.store.stats()

    @app.get("/api/export.csv")
    def export_csv() -> StreamingResponse:
        rows = app.state.store.list(None, 500)
        output = io.StringIO()
        fields = ["ts", "severity", "detector", "rule", "src", "dst", "message", "capture_name"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            safe = dict(row)
            for key in fields:
                value = safe.get(key)
                if isinstance(value, str) and value[:1] in {"=", "+", "-", "@", "\t", "\r"}:
                    safe[key] = "'" + value
            writer.writerow(safe)
        output.seek(0)
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=nexus-ids-alerts.csv"})

    return app


app = create_app()
