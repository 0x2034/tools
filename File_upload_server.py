import sys
import os
import cgi
from http.server import HTTPServer, BaseHTTPRequestHandler

class FileUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_type, _ = cgi.parse_header(self.headers['Content-Type'])
        if content_type == 'multipart/form-data':
            form_data = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            if 'file' in form_data:
                file_item = form_data['file']
                # Get the directory of the script
                script_dir = os.path.dirname(__file__)
                filename = os.path.join(script_dir, os.path.basename(file_item.filename))
                with open(filename, 'wb') as f:
                    f.write(file_item.file.read())
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'File uploaded successfully')
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'File field not found in form data')
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Bad request')

def run(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, FileUploadHandler)
    print(f"Server started on port {port}")
    httpd.serve_forever()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python file_upload_server.py <port>")
        sys.exit(1)
    
    port = int(sys.argv[1])
    run(port)
