from __future__ import annotations

import importlib.util
import threading
from pathlib import Path
from urllib.parse import quote
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


def _module():
    script = Path(__file__).resolve().parents[1] / "scripts" / "serve_build_asset.py"
    spec = importlib.util.spec_from_file_location("serve_build_asset", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_local_archive_server_exposes_only_the_expected_asset(tmp_path: Path) -> None:
    asset = tmp_path / "trusted archive.zip"
    asset.write_bytes(b"verified-build-input")
    server = _module().create_server(asset, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        asset_url = f"{base_url}/{quote(asset.name)}"
        with urlopen(asset_url) as response:
            assert response.status == 200
            assert response.read() == asset.read_bytes()
            assert response.headers["Content-Type"] == "application/zip"
        with urlopen(Request(asset_url, method="HEAD")) as response:
            assert int(response.headers["Content-Length"]) == asset.stat().st_size
        with pytest.raises(HTTPError) as error:
            urlopen(f"{base_url}/other.zip")
        assert error.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_local_archive_server_rejects_non_loopback_bind(tmp_path: Path) -> None:
    asset = tmp_path / "archive.zip"
    asset.write_bytes(b"data")
    with pytest.raises(ValueError, match="loopback"):
        _module().create_server(asset, "0.0.0.0", 0)
