"""Contract for the served workbench assets after conflict 1 was resolved (P2-S unblocking).

WHY THIS TEST EXISTS: `src/threat_report_agent/static/` was renamed to `assets/` so that plan 7.7 can make
`static/` the static-recovery PACKAGE. The mount URL was deliberately kept as `/static`, which means the move is
correct exactly when every browser-visible URL is unchanged - and MEASURED, no test in the suite requested
`/static` before this file existed, so nothing would have noticed if the rename had broken the mount.

The assertions are therefore about the HTTP surface, not about the directory name:

  * `/static/index.html`, `/static/app.js`, `/static/styles.css` each return 200 with a non-empty body;
  * `/` returns the index document;
  * `index.html` still links `/static/styles.css`, so the page and the mount cannot drift apart silently.

    python -m pytest -q tests/test_workbench_assets.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.main import create_app  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"

#: The served assets, with the marker each must contain so a 200 with the wrong body cannot pass.
ASSETS = {
    "index.html": "<html",
    "app.js": "use strict",
    "styles.css": "{",
}


@pytest.fixture
def client(test_settings) -> TestClient:
    return TestClient(create_app(test_settings))


def test_every_asset_is_served_at_its_url(client: TestClient) -> None:
    for name, marker in ASSETS.items():
        response = client.get(f"/static/{name}")
        assert response.status_code == 200, f"/static/{name} returned {response.status_code}"
        assert response.content, f"/static/{name} served an empty body"
        assert marker in response.text, f"/static/{name} served a body without {marker!r}"


def test_the_index_route_serves_the_same_document(client: TestClient) -> None:
    root = client.get("/")
    assert root.status_code == 200
    assert "text/html" in root.headers.get("content-type", "")
    assert root.text == client.get("/static/index.html").text, (
        "`/` and `/static/index.html` disagree, so the FileResponse path and the mount point at different files"
    )


def test_the_index_still_links_the_mounted_stylesheet(client: TestClient) -> None:
    """The page and the mount are two independent strings; this pins them together."""
    assert "/static/styles.css" in client.get("/static/index.html").text, (
        "index.html no longer references the mounted stylesheet URL"
    )
    assert client.get("/static/styles.css").status_code == 200


def test_the_asset_directory_is_not_a_python_package() -> None:
    """The conflict's whole point: `assets/` must not become importable, so P2-S can take `static/`."""
    assert (PACKAGE / "assets").is_dir(), "the served assets are not where main.py expects them"
    assert not (PACKAGE / "assets" / "__init__.py").exists(), (
        "assets/ grew an __init__.py, which would make it a package under `packages.find` and change the published "
        "artefacts - the reason conflict 1 was resolved by renaming the ASSETS and not the package"
    )
    assert not (PACKAGE / "static" / "app.js").exists(), (
        "the old static/ asset path came back; `static/` is reserved for the static-recovery package"
    )
