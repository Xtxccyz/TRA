from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("asset", type=Path)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument(
        "--ready-file",
        type=Path,
        help="write the selected TCP port after the loopback listener is ready",
    )
    return parser


def create_server(asset: Path, bind: str, port: int) -> ThreadingHTTPServer:
    asset = asset.resolve(strict=True)
    if bind not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("build asset server may bind only to a loopback address")
    route = f"/{asset.name}"

    class SingleAssetHandler(BaseHTTPRequestHandler):
        def _send_asset_headers(self) -> bool:
            request = urlsplit(self.path)
            if request.query or unquote(request.path) != route:
                self.send_error(404)
                return False
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(asset.stat().st_size))
            self.end_headers()
            return True

        def do_HEAD(self) -> None:
            self._send_asset_headers()

        def do_GET(self) -> None:
            if not self._send_asset_headers():
                return
            with asset.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    self.wfile.write(chunk)

        def log_message(self, format: str, *values: object) -> None:
            return

    return ThreadingHTTPServer((bind, port), SingleAssetHandler)


def main() -> None:
    args = build_parser().parse_args()
    server = create_server(args.asset, args.bind, args.port)
    if args.ready_file:
        ready_file = args.ready_file.resolve()
        ready_file.parent.mkdir(parents=True, exist_ok=True)
        ready_file.write_text(f"{server.server_port}\n", encoding="ascii")
    server.serve_forever()


if __name__ == "__main__":
    main()
