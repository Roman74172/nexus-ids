from __future__ import annotations

import io

from fastapi.testclient import TestClient

from sentinel.pcap import PcapWriter
from sentinel.web import create_app
from tools.gen_pcap import generate_attacks


def _capture() -> bytes:
    output = io.BytesIO()
    writer = PcapWriter(output)
    for packet in generate_attacks():
        writer.write(packet)
    return output.getvalue()


def test_health_and_dashboard(tmp_path) -> None:
    client = TestClient(create_app(tmp_path / "alerts.db"))
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health["service"] == "nexus-ids-web"
    assert health["version"] == "1.0.0"
    assert "NEXUS" in client.get("/").text


def test_upload_analyzes_and_persists_alerts(tmp_path) -> None:
    client = TestClient(create_app(tmp_path / "alerts.db"))
    response = client.post("/api/analyze", files={"file": ("attacks.pcap", _capture(), "application/octet-stream")})
    assert response.status_code == 200
    body = response.json()
    assert body["packets_analyzed"] > 0
    assert body["alerts_found"] > 0
    assert {a["detector"] for a in body["alerts"]} >= {"port_scan", "syn_flood", "arp_spoof"}
    assert client.get("/api/stats").json()["total_alerts"] == body["alerts_found"]
    assert client.get("/api/alerts").json()["alerts"]
    assert "text/csv" in client.get("/api/export.csv").headers["content-type"]


def test_upload_rejects_wrong_extension_and_bad_capture(tmp_path) -> None:
    client = TestClient(create_app(tmp_path / "alerts.db"))
    assert client.post("/api/analyze", files={"file": ("notes.txt", b"hello")}).status_code == 415
    assert client.post("/api/analyze", files={"file": ("broken.pcap", b"not a capture")}).status_code == 422


def test_severity_filter_validation(tmp_path) -> None:
    client = TestClient(create_app(tmp_path / "alerts.db"))
    assert client.get("/api/alerts?severity=urgent").status_code == 400
