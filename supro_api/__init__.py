"""SuproAPI - Lightweight REST API framework built with Python."""

__version__ = "1.0.0"
__author__ = "SuproCode"

import json
import hashlib
import hmac
import time
import functools
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from typing import Callable, Dict, List, Optional, Tuple, Any


class Request:
    """HTTP Request object."""

    def __init__(self, method: str, path: str, headers: dict, body: bytes, query: dict):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body
        self.query = query
        self.json = self._parse_json()
        self.params = {}

    def _parse_json(self) -> Optional[dict]:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None


class Response:
    """HTTP Response object."""

    def __init__(self):
        self.status_code = 200
        self.body = ""
        self.headers = {"Content-Type": "application/json"}

    def json(self, data: dict, status: int = 200) -> "Response":
        self.body = json.dumps(data, indent=2)
        self.status_code = status
        self.headers["Content-Type"] = "application/json"
        return self

    def text(self, message: str, status: int = 200) -> "Response":
        self.body = message
        self.status_code = status
        self.headers["Content-Type"] = "text/plain"
        return self

    def html(self, content: str, status: int = 200) -> "Response":
        self.body = content
        self.status_code = status
        self.headers["Content-Type"] = "text/html"
        return self

    def redirect(self, url: str, status: int = 302) -> "Response":
        self.status_code = status
        self.headers["Location"] = url
        return self

    def set_header(self, key: str, value: str) -> "Response":
        self.headers[key] = value
        return self


class Router:
    """URL Router with support for path parameters."""

    def __init__(self):
        self.routes: Dict[str, Dict[str, Callable]] = {}
        self.middleware: List[Callable] = []

    def add_route(self, method: str, path: str, handler: Callable):
        pattern = self._path_to_pattern(path)
        if pattern not in self.routes:
            self.routes[pattern] = {}
        self.routes[pattern][method.upper()] = handler

    def _path_to_pattern(self, path: str) -> str:
        parts = path.strip("/").split("/")
        pattern_parts = []
        for part in parts:
            if part.startswith("{") and part.endswith("}"):
                pattern_parts.append("*")
            else:
                pattern_parts.append(part)
        return "/".join(pattern_parts)

    def _extract_params(self, path: str, pattern: str) -> dict:
        path_parts = path.strip("/").split("/")
        pattern_parts = pattern.strip("/").split("/")
        params = {}
        for p_part, r_part in zip(pattern_parts, path_parts):
            if p_part == "*":
                param_name = r_part
                params[param_name] = r_part
        return params

    def match(self, method: str, path: str) -> Tuple[Optional[Callable], dict]:
        path_clean = path.strip("/")
        for pattern, handlers in self.routes.items():
            pattern_parts = pattern.strip("/").split("/")
            path_parts = path_clean.split("/")
            if len(pattern_parts) != len(path_parts):
                continue
            match = True
            for pp, rp in zip(pattern_parts, path_parts):
                if pp != "*" and pp != rp:
                    match = False
                    break
            if match and method.upper() in handlers:
                params = self._extract_params(path, pattern)
                return handlers[method.upper()], params
        return None, {}


class JWTAuth:
    """Simple JWT-like authentication using HMAC."""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def generate_token(self, payload: dict, expires_in: int = 3600) -> str:
        payload["exp"] = int(time.time()) + expires_in
        payload_json = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            self.secret_key.encode(), payload_json.encode(), hashlib.sha256
        ).hexdigest()
        import base64
        token = base64.urlsafe_b64encode(payload_json.encode()).decode() + "." + signature
        return token

    def verify_token(self, token: str) -> Optional[dict]:
        try:
            import base64
            payload_b64, signature = token.rsplit(".", 1)
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
            expected_sig = hmac.new(
                self.secret_key.encode(), payload_json.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected_sig):
                return None
            payload = json.loads(payload_json)
            if payload.get("exp", 0) < time.time():
                return None
            return payload
        except Exception:
            return None


class SuproAPI:
    """Main application class."""

    def __init__(self, name: str = "SuproAPI"):
        self.name = name
        self.router = Router()
        self.jwt = None
        self._before_requests = []
        self._error_handlers = {}
        self._docs = {}

    def configure_jwt(self, secret_key: str):
        self.jwt = JWTAuth(secret_key)

    def route(self, path: str, methods: List[str] = None):
        if methods is None:
            methods = ["GET"]

        def decorator(func):
            for method in methods:
                self.router.add_route(method, path, func)
            self._docs[f"{method} {path}"] = {
                "handler": func.__name__,
                "doc": func.__doc__ or "No description",
            }
            return func

        return decorator

    def get(self, path: str):
        return self.route(path, methods=["GET"])

    def post(self, path: str):
        return self.route(path, methods=["POST"])

    def put(self, path: str):
        return self.route(path, methods=["PUT"])

    def delete(self, path: str):
        return self.route(path, methods=["DELETE"])

    def before_request(self, func):
        self._before_requests.append(func)
        return func

    def error_handler(self, status_code: int):
        def decorator(func):
            self._error_handlers[status_code] = func
            return func
        return decorator

    def get_docs(self) -> dict:
        return {
            "app": self.name,
            "version": __version__,
            "endpoints": self._docs,
        }

    def run(self, host: str = "0.0.0.0", port: int = 8000, debug: bool = False):
        app = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def do_PUT(self):
                self._handle("PUT")

            def do_DELETE(self):
                self._handle("DELETE")

            def _handle(self, method):
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length > 0 else b""

                request = Request(
                    method=method,
                    path=parsed.path,
                    headers=dict(self.headers),
                    body=body,
                    query=query,
                )

                handler, params = app.router.match(method, parsed.path)
                if handler is None:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Not Found"}).encode())
                    return

                request.params = params

                for before in app._before_requests:
                    result = before(request)
                    if result:
                        self._send_response(result)
                        return

                response = Response()
                result = handler(request, response)
                self._send_response(result if result else response)

            def _send_response(self, response):
                self.send_response(response.status_code)
                for key, value in response.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                if response.body:
                    self.wfile.write(response.body.encode())

            def log_message(self, format, *args):
                if debug:
                    print(f"[{app.name}] {args[0]}")

        server = HTTPServer((host, port), Handler)
        print(f"\n  SuproAPI v{__version__}")
        print(f"  Running on http://{host}:{port}")
        print(f"  Docs: http://{host}:{port}/docs\n")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped.")
            server.server_close()
