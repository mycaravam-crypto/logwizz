"""Test-only HTTPS endpoint: prints each notification body it receives."""
import http.server
import ssl


class Sink(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        print(self.rfile.read(int(self.headers["Content-Length"])).decode(), flush=True)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


server = http.server.HTTPServer(("0.0.0.0", 8443), Sink)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/certs/sink.pem")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
