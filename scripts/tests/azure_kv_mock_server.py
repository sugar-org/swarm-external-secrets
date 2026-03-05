#!/usr/bin/env python3
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


HOST = os.getenv("AZURE_KV_MOCK_HOST", "127.0.0.1")
PORT = int(os.getenv("AZURE_KV_MOCK_PORT", "8081"))
TOKEN = os.getenv("AZURE_KV_MOCK_TOKEN", "smoke-token")
TENANT = os.getenv("AZURE_KV_MOCK_TENANT", "smoke-tenant")

SECRETS = {}


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        body = self.rfile.read(length).decode("utf-8")
        return json.loads(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/health":
            return self._json(200, {"status": "ok"})

        # Key Vault Get Secret: /secrets/{name} or /secrets/{name}/{version}
        if path.startswith("/secrets/"):
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {TOKEN}":
                challenge = (
                    f'Bearer authorization="https://login.microsoftonline.com/{TENANT}", '
                    'resource="https://vault.azure.net"'
                )
                return self._json(401, {"error": "unauthorized"}, {"WWW-Authenticate": challenge})

            parts = [p for p in path.split("/") if p]
            if len(parts) < 2:
                return self._json(400, {"error": "invalid secret path"})
            name = parts[1]
            if name not in SECRETS:
                return self._json(404, {"error": {"code": "SecretNotFound", "message": "secret not found"}})

            value = SECRETS[name]
            api_version = parse_qs(parsed.query).get("api-version", ["7.4"])[0]
            return self._json(
                200,
                {
                    "value": value,
                    "id": f"http://{HOST}:{PORT}/secrets/{name}/smoke-version",
                    "attributes": {"enabled": True},
                    "contentType": "text/plain",
                    "tags": {"source": "smoke-test"},
                    "managed": False,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "apiVersion": api_version,
                },
            )

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        # Control endpoint for smoke scripts to seed/rotate secrets.
        if self.path == "/mock/set":
            body = self._read_body()
            name = body.get("name")
            value = body.get("value")
            if not name:
                return self._json(400, {"error": "name is required"})
            if value is None:
                return self._json(400, {"error": "value is required"})
            SECRETS[name] = value
            return self._json(200, {"ok": True, "name": name})

        return self._json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        # Keep CI output concise.
        return


def main():
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Azure KV mock listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
