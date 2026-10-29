"""
CCDC Module 1 — Local Mock Service Harness
Simulates scored network services on localhost for connection triage and inspection.

Ports:
  - 8080/tcp: Scored Web Service (HTTP 200 OK with SLA heartbeat)
  - 9000/tcp: Scored TCP Echo Service (Echoes received bytes back to client)

Usage:
  python mock_ccdc_services.py
"""

import sys
import time
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

HTTP_PORT = 8080
ECHO_PORT = 9000
HOST = "127.0.0.1"


class ScoredHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"CCDC_SERVICE_STATUS: OK - UPTIME_SLA_PASSED\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Clean timestamped log
        sys.stdout.write(f"[{time.strftime('%H:%M:%S')}] [HTTP 8080] {self.client_address[0]}:{self.client_address[1]} - {format % args}\n")
        sys.stdout.flush()


def run_http_server():
    server = HTTPServer((HOST, HTTP_PORT), ScoredHTTPHandler)
    print(f"[*] Scored HTTP service listening on {HOST}:{HTTP_PORT}")
    try:
        server.serve_forever()
    except Exception:
        pass


def run_echo_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, ECHO_PORT))
    sock.listen(5)
    print(f"[*] Scored Echo service listening on {HOST}:{ECHO_PORT}")

    while True:
        try:
            conn, addr = sock.accept()
            sys.stdout.write(f"[{time.strftime('%H:%M:%S')}] [ECHO 9000] TCP 3-way handshake completed with {addr[0]}:{addr[1]}\n")
            sys.stdout.flush()
            data = conn.recv(1024)
            if data:
                conn.sendall(b"ACK_ECHO: " + data)
            conn.close()
        except Exception:
            break


def main():
    print("=" * 60)
    print(" CCDC Local Mock Service Harness (Module 1)")
    print(" Simulating active scored services on localhost")
    print("=" * 60)

    t1 = threading.Thread(target=run_http_server, daemon=True)
    t2 = threading.Thread(target=run_echo_server, daemon=True)

    t1.start()
    t2.start()

    print(f"\n[+] Both services are online.")
    print(f"[+] Press Ctrl+C at any time to shut down the harness.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down mock service harness. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
