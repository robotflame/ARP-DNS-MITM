import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import logging, os

class Handler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logging.info("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), fmt%args)

def main():
    ap = argparse.ArgumentParser(description='Minimal demo HTTP server. Serves current dir.')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--dir', default='webserver')
    args = ap.parse_args()

    os.makedirs(args.dir, exist_ok=True)
    index = os.path.join(args.dir, 'index.html')
    if not os.path.exists(index):
        with open(index, 'w') as f:
            f.write('<html><head><title>MITM Demo</title></head>'
                    '<body><h1>It worked!</h1><p>You were redirected here via DNS spoof (lab demo).</p></body></html>')

    os.chdir(args.dir)
    logging.basicConfig(filename='../evidence/webserver.log', level=logging.INFO, format='%(message)s')
    httpd = ThreadingHTTPServer(('0.0.0.0', args.port), Handler)
    print(f'[*] Serving {args.dir} on port {args.port} ... Ctrl+C to stop.')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\n[!] Stopping server. Logs saved to evidence/webserver.log')

if __name__ == '__main__':
    main()
