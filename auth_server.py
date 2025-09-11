#!/usr/bin/env python3
import http.server
import socketserver
import base64
import json
import time
from datetime import datetime

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        auth_header = self.headers.get('Authorization')
        
        # Log authentication attempt
        timestamp = datetime.now().isoformat() + 'Z'
        client_ip = self.client_address[0]
        
        if auth_header and auth_header.startswith('Basic '):
            encoded = auth_header[6:]
            try:
                decoded = base64.b64decode(encoded).decode('utf-8')
                username, password = decoded.split(':', 1)
                
                # Log failed attempt
                log_entry = {
                    'timestamp': timestamp,
                    'Image': '/usr/bin/python3',
                    'CommandLine': f'HTTP Auth attempt: {username}:{password}',
                    'User': 'www-data',
                    'source_ip': client_ip,
                    'auth_result': 'failed',
                    'category': 'application',
                    'product': 'web'
                }
                
                with open('/data/events.ndjson', 'a') as f:
                    f.write(json.dumps(log_entry) + '\n')
                
                if username == 'admin' and password == 'admin123':
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'Access granted!')
                    return
                    
            except:
                pass
                
        # Send 401 for failed auth
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
        self.end_headers()
        self.wfile.write(b'Authentication required')

if __name__ == '__main__':
    with socketserver.TCPServer(('0.0.0.0', 8000), AuthHandler) as httpd:
        print('Server running on port 8000...')
        httpd.serve_forever()
