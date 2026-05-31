#!/usr/bin/env python3
"""
Production launcher for the Kali MCP API server.

Serves the existing Flask `app` (defined in server_patched.py) through Waitress,
a production-grade pure-Python WSGI server. This removes Flask's built-in
development-server warning:

    "WARNING: This is a development server. Do not use it in a production
     deployment. Use a production WSGI server instead."

Usage:
    python3 serve_prod.py --ip 0.0.0.0 --port 5000 [--threads 8]

The Flask app and all its routes (tools + /api/msf/*) come from server_patched.py
unchanged; this file only swaps the server that runs it.
"""
import argparse
import importlib.util
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("kali-mcp-prod")

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_FILE = os.path.join(HERE, "server_patched.py")


def load_app():
    """Import the Flask `app` object from server_patched.py without running it."""
    spec = importlib.util.spec_from_file_location("kali_server_app", SERVER_FILE)
    module = importlib.util.module_from_spec(spec)
    # Guard against the server's own __main__ block executing app.run().
    sys.argv = [SERVER_FILE]
    spec.loader.exec_module(module)
    return module.app


def main():
    parser = argparse.ArgumentParser(description="Production WSGI launcher for the Kali MCP API server")
    parser.add_argument("--ip", default="0.0.0.0", help="Address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    parser.add_argument("--threads", type=int, default=8, help="Waitress worker threads (default: 8)")
    args = parser.parse_args()

    from waitress import serve

    app = load_app()
    logger.info("Starting Kali MCP API server (Waitress) on %s:%s with %d threads",
                args.ip, args.port, args.threads)
    serve(app, host=args.ip, port=args.port, threads=args.threads, ident="kali-mcp")


if __name__ == "__main__":
    main()
