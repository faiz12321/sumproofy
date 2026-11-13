"""Start SumProofy and open it in the browser.

Threads: the web server runs on its own daemon thread (started by serve()).
The main thread runs the file-picker dialog loop (tkinter must live on the
main thread), or just waits when there is no picker.
"""
import argparse
import webbrowser

from .picker import make_picker
from .server import serve


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sumproofy",
                                 description="Check a downloaded file against the maker's official fingerprint.")
    ap.add_argument("--port", type=int, default=0, help=argparse.SUPPRESS)
    ap.add_argument("--token", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--no-browser", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--no-picker", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    picker, run_main = make_picker(disabled=args.no_picker)
    httpd, port, token = serve(port=args.port, token=args.token,
                               browser=(picker.pick if picker else None))
    url = f"http://127.0.0.1:{port}/"
    print("SumProofy is running.")
    print(f"Open this address in your browser: {url}")
    print("Close this window to stop it.")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        run_main()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
