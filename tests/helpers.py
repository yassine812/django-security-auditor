"""Test helpers: in-process fake Django-like HTTP server used by the
network/DAST/security-test suites (stands in for a real isolated app)."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

XSS_PAYLOAD_MARKER = "<dsosec9x7>alert(1)</dsosec9x7>"
XSS_PAYLOAD_MARKER_T = "<dsosec-t7>alert(1)</dsosec-t7>"


def make_handler(secure: bool):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):  # silence
            pass

        def _headers(self, status=200, extra=None, cookies=None):
            self.send_response(status)
            if not secure:
                self.send_header("Content-Type", "text/html")
            else:
                self.send_header("Content-Type", "text/html")
                self.send_header("Strict-Transport-Security", "max-age=31536000")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "same-origin")
                self.send_header("Content-Security-Policy", "default-src 'self'")
                self.send_header("Permissions-Policy", "geolocation=(), camera=()")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            for c in (cookies or []):
                self.send_header("Set-Cookie", c)

        def _body(self, text):
            data = text.encode()
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            path = parsed.path

            if path == "/":
                cookie = ("sessionid=abc123; Path=/; HttpOnly; Secure" if secure
                          else "sessionid=abc123; Path=/")
                self._headers(200, cookies=[cookie])
                self._body("<html><body>Django app home</body></html>")
            elif path in ("/.env", "/.git/HEAD") and not secure:
                self._headers(200)
                self._body("SECRET_KEY=leakedsecretvalue\n" if path == "/.env"
                           else "ref: refs/heads/main\n")
            elif path == "/admin/":
                if secure:
                    self._headers(302, {"Location": "/admin/login/"})
                    self._body("")
                else:
                    self._headers(200)
                    self._body("<h1>Django administration</h1>")
            elif path == "/api/docs/" and not secure:
                self._headers(200)
                self._body("<html>swagger-ui openapi</html>")
            elif path == "/search/":
                q = (qs.get("q") or [""])[0]
                if not secure:
                    self._headers(200)
                    self._body(f"<html>results for {q}</html>")     # reflects unencoded
                else:
                    self._headers(200)
                    self._body(f"<html>results for {q.replace('<', '&lt;')}</html>")
            elif path == "/doc/" and not secure:
                ident = (qs.get("id") or [""])[0]
                if "'" in ident:
                    self._headers(500)
                    self._body('django.db.utils.OperationalError: near "\'": syntax error')
                else:
                    self._headers(200)
                    self._body("<html>doc</html>")
            elif path == "/go/":
                nxt = (qs.get("next") or [""])[0]
                if not secure and nxt.startswith("http"):
                    self._headers(302, {"Location": nxt})
                    self._body("")
                else:
                    self._headers(302, {"Location": "/"})
                    self._body("")
            elif path == "/download/" and not secure:
                f = (qs.get("file") or [""])[0]
                if ".." in f:
                    self._headers(200)
                    self._body("root:x:0:0:root:/root:/bin/bash\n")
                else:
                    self._headers(404)
                    self._body("not found")
            else:
                if secure:
                    self._headers(302, {"Location": "/accounts/login/"})
                    self._body("")
                else:
                    self._headers(404)
                    if "DEBUG = True" in self.server.debug_marker:
                        self._body("<h1>Server Error</h1><pre>You're seeing this error "
                                   "because you have DEBUG = True in your Django "
                                   "settings file. Traceback...</pre>")
                    else:
                        self._body("<h1>Not Found</h1>")

        def do_POST(self):
            if secure:
                self._headers(403)
                self._body("CSRF verification failed. Request aborted.")
            else:
                self._headers(200)
                self._body('{"status": "ok"}')

    return Handler


class FakeDjangoServer:
    def __init__(self, secure: bool = False):
        handler = make_handler(secure)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.debug_marker = "" if secure else "DEBUG = True"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
