"""After `ngrok http 8000` is running: find the public https URL, check it end to end exactly as the judge will, and print the address to submit.

    python scripts/public_url.py

Reads the URL from ngrok's local API (http://127.0.0.1:4040), then runs scripts/endpoint_check.py against it.  Exit code 0 = ready to submit.
Notes: the free ngrok URL changes every time ngrok restarts, so do not restart it once the URL has been submitted; the service must stay running.
"""
import json
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def public_url() -> str:
    with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=5) as r:
        tunnels = json.load(r).get("tunnels", [])
    https = [t["public_url"] for t in tunnels if t.get("public_url", "").startswith("https://")]
    if not https:
        raise RuntimeError("no https tunnel found: is `ngrok http 8000` running?")
    return https[0]


def main() -> int:
    try:
        base = public_url()
    except Exception as e:
        print(f"Cannot find the ngrok tunnel ({type(e).__name__}: {e}).")
        print("Start the service (scripts\\start_service.bat), then in another window run:  ngrok http 8000")
        return 1
    print("public base URL :", base)
    print("endpoint to submit:", base + "/scan")
    print("batch endpoint  :", base + "/batch")
    print("health          :", base + "/health")
    print()
    rc = subprocess.call([sys.executable, os.path.join(HERE, "endpoint_check.py"), base])
    if rc == 0:
        print("\nReady. Submit:", base + "/scan")
        print("Keep this service window and the ngrok window open, keep the laptop awake, do not restart ngrok.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
