import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Routes:
    def get(self, _path):
        return lambda fn: fn


app = Routes()


def add(a, b):
    zero = a == 0
    if zero:
        return b
    return a + b


@app.get("/health")
def health():
    return {"ok": True}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps(health()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    import sys
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
