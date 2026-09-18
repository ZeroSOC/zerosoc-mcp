from __future__ import annotations

import json
from pathlib import Path

import pytest
from zerosoc_defender_xdr.__main__ import main
from zerosoc_defender_xdr.manifest import manifest

MANIFEST = Path(__file__).parents[3] / "servers" / "defender-xdr" / "capabilities.manifest.json"


def test_the_committed_manifest_is_the_one_the_code_generates() -> None:
    """Regenerate with: uv run zerosoc-defender-xdr manifest --out servers/defender-xdr/capabilities.manifest.json"""
    assert json.loads(MANIFEST.read_text()) == manifest()


def test_manifest_command_writes_the_file(tmp_path: Path) -> None:
    target = tmp_path / "m.json"
    assert main(["manifest", "--out", str(target)]) == 0
    assert json.loads(target.read_text())["server"] == "defender-xdr"


def test_probe_without_credentials_says_what_to_set(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)
    assert main(["probe"]) == 2
    assert "DEFENDER_CLIENT_SECRET" in capsys.readouterr().err


def test_evidence_command_writes_rows_the_skills_script_reads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every page, as a plain list of rows; the counts go to standard error."""
    pages: list[int] = []

    class Client:
        def __init__(self, _credential: object) -> None: ...

        async def get_incident_evidence(
            self, incident_id: str, top: int, skip: int
        ) -> dict[str, object]:
            pages.append(skip)
            rows = [
                {"type": "ip", "name": f"10.0.0.{n}", "alert_ids": ["a"]}
                for n in range(skip, min(skip + top, 3))
            ]
            return {
                "incidentId": incident_id,
                "entityCount": 3,
                "alertCount": 1,
                "rowCount": 3,
                "alertsTruncated": False,
                "entities": rows,
                "hasMore": skip + top < 3,
            }

        async def aclose(self) -> None: ...

    monkeypatch.setattr("zerosoc_defender_xdr.__main__.DefenderClient", Client)
    monkeypatch.setattr("zerosoc_defender_xdr.__main__.PAGE", 2)
    for name in ("DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"):
        monkeypatch.setenv(name, "x")
    target = tmp_path / "evidence.json"

    assert main(["evidence", "14", "--out", str(target)]) == 0

    rows = json.loads(target.read_text())
    assert [r["name"] for r in rows] == ["10.0.0.0", "10.0.0.1", "10.0.0.2"] and pages == [0, 2]
    assert "3 entities" in capsys.readouterr().err
