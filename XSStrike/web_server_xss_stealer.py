from http.server import SimpleHTTPRequestHandler, HTTPServer
import json

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers to allow all origins
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With')
        super().end_headers()

    def do_OPTIONS(self):
        # Handle OPTIONS preflight request
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        # Handling POST request to receive cookies
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data)
        
        cookie_data = data.get('cookie', '')
        if cookie_data:
            print(f"Received cookies: {cookie_data}")
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Cookies received")

def run(server_class=HTTPServer, handler_class=CORSRequestHandler):
    server_address = ('', 8788)  # Listening on port 8788
    httpd = server_class(server_address, handler_class)
    print('Starting server on port 8788...')
    httpd.serve_forever()

if __name__ == '__main__':
    run()
