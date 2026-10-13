"""Fixed local ingress relay; no arbitrary URLs, headers, proxying or request logging."""

import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer

LIMIT = 65536


class Relay(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.forward()

    def do_POST(self) -> None:
        self.forward()

    def forward(self) -> None:
        self.connection.settimeout(45)
        upstream = http.client.HTTPConnection("model", 11434, timeout=45)
        try:
            allowed = {
                ("GET", "/api/version"),
                ("GET", "/api/tags"),
                ("POST", "/api/show"),
                ("POST", "/api/generate"),
            }
            if (self.command, self.path) not in allowed:
                self.send_error(404)
                return
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) > 1 or self.headers.get("Transfer-Encoding"):
                self.send_error(400)
                return
            length = int(lengths[0]) if lengths else 0
            if not 0 <= length <= LIMIT:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.send_error(400)
                return
            upstream.request(
                self.command,
                self.path,
                body=body,
                headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
            )
            response = upstream.getresponse()
            result = response.read(LIMIT + 1)
            if (
                len(result) > LIMIT
                or response.getheader("Content-Encoding", "identity") != "identity"
            ):
                self.send_error(502)
                return
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
        except Exception:
            # No traceback, upstream body, prompt or source text in logs/errors.
            self.close_connection = True
        finally:
            upstream.close()


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Relay).serve_forever()
