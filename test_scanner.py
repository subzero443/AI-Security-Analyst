import asyncio
import json
import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from backend import main
from backend.main import analyze_findings, app, build_findings, extract_technology_signals, normalize_target, probe_web_ports


async def post_scan(target: str, authorized: bool) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post("/api/scan", json={"target": target, "authorized": authorized})


def test_normalize_target_keeps_only_authorized_origin() -> None:
    origin, hostname, port, scheme = normalize_target("https://example.com/app")

    assert origin == "https://example.com"
    assert hostname == "example.com"
    assert port == 443
    assert scheme == "https"


def test_normalize_target_rejects_private_and_nonstandard_targets() -> None:
    for target in (
        "http://127.0.0.1",
        "http://192.168.1.1",
        "http://localhost",
        "https://example.com:8443",
        "https://example.com:0",
        "https://user:pass@example.com",
        "https://example.com/?token=secret",
    ):
        try:
            normalize_target(target)
        except ValueError:
            continue
        raise AssertionError(f"Unsafe target was accepted: {target}")


def test_build_findings_and_analysis_are_evidence_based() -> None:
    scan = {
        "target": "https://example.com",
        "requestCount": 2,
        "pages": [{
            "path": "/",
            "status": 200,
            "headers": {"server": "ExampleEdge/1.0"},
            "cookies": [],
        }],
        "technologySignals": [{"source": "Server header", "value": "ExampleEdge/1.0"}],
    }

    findings = build_findings(scan)
    analysis = analyze_findings(findings, scan)

    assert any(finding["title"] == "Content-Security-Policy header not observed" for finding in findings)
    assert any(finding["title"] == "Server technology details disclosed" for finding in findings)
    assert analysis["findingCount"] == len(findings)
    assert analysis["engine"] == "evidence-rules-v1"
    assert "2 bounded GET request(s)" in analysis["limitations"][-1]


def test_build_findings_does_not_infer_from_failed_root_request() -> None:
    scan = {
        "target": "https://example.com",
        "requestCount": 1,
        "pages": [{"path": "/", "status": None, "headers": {}, "cookies": []}],
    }

    assert build_findings(scan) == []


def test_scan_api_requires_explicit_authorization() -> None:
    response = asyncio.run(post_scan("https://example.com", authorized=False))

    assert response.status_code == 403


def test_scan_api_rejects_loopback_before_network_access() -> None:
    response = asyncio.run(post_scan("http://127.0.0.1", authorized=True))

    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"]


def test_model_analysis_filters_unknown_priority_ids() -> None:
    findings = [{"id": "LIVE-001", "severity": "Low", "confidence": 98, "title": "Header absent", "category": "Headers", "observed": "Not present", "impact": "Limited", "recommendation": "Set the header", "evidence": "Observed response"}]
    scan = {"target": "https://example.com", "requestCount": 1}
    local = analyze_findings(findings, {**scan, "pages": [{"path": "/", "status": 200}]})
    completion = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({
        "summary": "Review the observed header.",
        "priorities": [
            {"findingId": "LIVE-001", "reason": "Directly observed."},
            {"findingId": "INVENTED-999", "reason": "This ID must be discarded."},
        ],
    })) )])
    mock_client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock(return_value=completion))),
        close=AsyncMock(),
    )

    with patch.object(main, "OPENAI_API_KEY", "test-key"), patch.object(main, "AsyncOpenAI", return_value=mock_client):
        result = asyncio.run(main.analyze_with_model(findings, scan, local))

    assert result["engine"] == "openai-compatible"
    assert result["priorityFindingIds"] == ["LIVE-001"]


def test_model_analysis_falls_back_without_provider_key(monkeypatch) -> None:
    scan = {"target": "https://example.com", "requestCount": 0, "pages": []}
    local = analyze_findings([], scan)
    monkeypatch.setattr(main, "OPENAI_API_KEY", None)

    result = asyncio.run(main.analyze_with_model([], scan, local))

    assert result["engine"] == "evidence-rules-v1"
    assert "No AI provider is configured" in result["warning"]


def test_technology_and_database_names_require_public_disclosure() -> None:
    signals, databases = extract_technology_signals([{
        "path": "/",
        "headers": {"server": "ExampleServer", "x-powered-by": "PHP"},
        "body_preview": '<html><meta name="generator" content="Example CMS + PostgreSQL"></html>',
    }])

    assert {signal["source"] for signal in signals} == {"Server header", "X-Powered-By header", "HTML generator metadata"}
    assert databases == [{"technology": "PostgreSQL", "source": "HTML generator metadata"}]


def test_web_port_probe_checks_only_standard_web_ports(monkeypatch) -> None:
    attempted_ports: list[int] = []

    class FakeWriter:
        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def fake_open_connection(address: str, port: int, family: int):
        assert address == "93.184.216.34"
        assert family == socket.AF_INET
        attempted_ports.append(port)
        if port == 443:
            raise ConnectionRefusedError()
        return None, FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    results = asyncio.run(probe_web_ports([(socket.AF_INET, "93.184.216.34")]))

    assert attempted_ports == [80, 443]
    assert [item["state"] for item in results] == ["open", "closed"]


def test_scan_api_returns_real_scan_metadata_shape(monkeypatch) -> None:
    class FakeScanner:
        def __init__(self, origin: str, hostname: str, addresses: list[tuple[int, str]]) -> None:
            assert origin == "https://example.com"
            assert hostname == "example.com"
            assert addresses == [(socket.AF_INET, "93.184.216.34")]

        async def scan(self) -> dict:
            return {
                "id": "scan-id",
                "target": "https://example.com",
                "startedAt": "2026-10-01T00:00:00+00:00",
                "completedAt": "2026-10-01T00:00:01+00:00",
                "durationSeconds": 1.0,
                "requestCount": 1,
                "pagesChecked": 1,
                "methodology": "passive HTTP checks",
                "resolvedIps": ["93.184.216.34"],
                "webPorts": [{"port": 443, "service": "https", "state": "open", "address": "93.184.216.34"}],
                "technologySignals": [],
                "databaseDisclosures": [],
                "pages": [{
                    "path": "/",
                    "status": 200,
                    "headers": {"server": "ExampleServer"},
                    "cookies": [],
                    "redirect_chain": [],
                    "blocked_redirect": None,
                    "error": None,
                    "body_preview": "",
                }],
            }

    async def fake_resolve(hostname: str, port: int) -> list[tuple[int, str]]:
        assert hostname == "example.com"
        assert port == 443
        return [(socket.AF_INET, "93.184.216.34")]

    monkeypatch.setattr(main, "resolve_public_addresses", fake_resolve)
    monkeypatch.setattr(main, "PassiveScanner", FakeScanner)
    response = asyncio.run(post_scan("https://example.com", authorized=True))
    payload = response.json()

    assert response.status_code == 200
    assert payload["scan"]["resolvedIps"] == ["93.184.216.34"]
    assert payload["scan"]["webPorts"][0]["address"] == "93.184.216.34"
    assert payload["observations"][0]["status"] == 200