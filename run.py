#!/usr/bin/env python3

import argparse
import os
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.server import serve

def main():
    ap = argparse.ArgumentParser(prog="strata", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", nargs="?", help="E01, Ex01, or raw image")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8722)
    ap.add_argument("--examiner", default=os.environ.get("STRATA_EXAMINER"),
                    help="recorded against every action in the audit log")
    ap.add_argument("--browser", action="store_true",
                    help="open a browser at the UI once the server is up")
    ap.add_argument("--no-browser", action="store_true",
                    help=argparse.SUPPRESS)
    ap.add_argument("--read-only", action="store_true",
                    help="refuse export and report writing for this run")
    args = ap.parse_args()

    if args.image and not os.path.isfile(args.image):
        sys.exit("No such file: %s" % args.image)

    if args.browser and not args.no_browser and \
            args.host in ("127.0.0.1", "localhost"):
        try:
            webbrowser.open("http://%s:%d" % (args.host, args.port))
        except Exception:
            pass

    serve(args.host, args.port, args.image, args.examiner,
          read_only=args.read_only)

if __name__ == "__main__":
    main()
