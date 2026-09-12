from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler


HOST = "127.0.0.1"
PORT = 8080


class PhoenixFrontendHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate",
        )
        super().end_headers()


if __name__ == "__main__":
    print(f"PHOENIX frontend running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")

    server = ThreadingHTTPServer(
        (HOST, PORT),
        PhoenixFrontendHandler,
    )

    server.serve_forever()
