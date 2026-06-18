import functools
import http.server
import socketserver
from pathlib import Path


PORT = 8787
ROOT = Path(__file__).resolve().parents[1] / "web_ui"


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(ROOT))
    with ReusableTCPServer(("127.0.0.1", PORT), handler) as httpd:
        print(f"Phoenix Guardian Web UI: http://127.0.0.1:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()

