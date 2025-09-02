#!/usr/bin/env python3

import json
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import threading
from deep_analyzer import DeepSecurityAnalyzer

# Default port for the bridge server
PORT = 3002

class BridgeRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the JS-Python bridge"""
    
    def __init__(self, *args, **kwargs):
        self.analyzer = DeepSecurityAnalyzer()
        super().__init__(*args, **kwargs)
    
    def _set_headers(self, content_type="application/json"):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS"""
        self._set_headers()
    
    def do_GET(self):
        """Handle GET requests - just return a status message"""
        self._set_headers()
        response = {
            'status': 'running',
            'message': 'Python Deep Analyzer Bridge is running. Send POST requests to /analyze'
        }
        self.wfile.write(json.dumps(response).encode())
    
    def do_POST(self):
        """Handle POST requests with scan data"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            # Parse the JSON data
            scan_data = json.loads(post_data.decode('utf-8'))
            
            # Process based on the endpoint
            if self.path == '/analyze':
                # Analyze the scan results
                results = self.analyzer.analyze_scan_results(scan_data)
                
                # Send the response
                self._set_headers()
                self.wfile.write(json.dumps(results).encode())
            else:
                # Unknown endpoint
                self.send_response(404)
                self.end_headers()
                response = {'error': 'Unknown endpoint', 'status': 'failed'}
                self.wfile.write(json.dumps(response).encode())
                
        except Exception as e:
            # Handle errors
            self.send_response(500)
            self.end_headers()
            response = {'error': str(e), 'status': 'failed'}
            self.wfile.write(json.dumps(response).encode())


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    pass


def start_server(port=PORT):
    """Start the bridge server"""
    server = ThreadedHTTPServer(('localhost', port), BridgeRequestHandler)
    print(f"Starting Python Deep Analyzer Bridge on port {port}")
    
    # Start the server in a separate thread
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    return server


def main():
    """Main function to start the bridge server"""
    try:
        # Get port from command line args if provided
        port = PORT
        if len(sys.argv) > 1:
            port = int(sys.argv[1])
        
        # Start the server
        server = start_server(port)
        
        # Keep the main thread running
        print("Server is running. Press Ctrl+C to stop.")
        while True:
            try:
                input()
            except KeyboardInterrupt:
                break
        
        # Shutdown the server
        server.shutdown()
        print("Server stopped.")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()