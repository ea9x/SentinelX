"""Keep old local development bookmarks usable without exposing a dev server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Fixed destination: never derive the redirect host from request headers.
        path = self.path if self.path.startswith('/') else '/'
        self.send_response(302)
        self.send_header('Location', 'http://127.0.0.1:8088' + path)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', '0')
        self.end_headers()
    do_HEAD = do_GET
    def log_message(self, *_args):
        pass

if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 5173), RedirectHandler).serve_forever()
