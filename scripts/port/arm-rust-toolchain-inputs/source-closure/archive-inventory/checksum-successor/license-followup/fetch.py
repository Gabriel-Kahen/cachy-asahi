#!/usr/bin/env python3
"""Primary-source acquisition for this finite followup's coordinator allocation."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
MAX_REQUESTS, TOTAL_BYTES, ONE_BODY = 11, 5 * 1024**2, 1024**2


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def fetch(url, output, ledger):
    history = json.loads(ledger.read_text()) if ledger.exists() else {"requests": [], "body_bytes": 0}
    if output.exists():
        raise ValueError("new output required; use cached evidence without another request")
    opener = urllib.request.build_opener(NoRedirect)
    for _ in range(3):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in {"api.github.com", "raw.githubusercontent.com", "github.com"} or parsed.username or parsed.password:
            raise ValueError("only primary HTTPS GitHub endpoints are in this finite scope")
        if len(history["requests"]) >= MAX_REQUESTS:
            raise ValueError("coordinator11-request allocation exhausted")
        event = {"ordinal": len(history["requests"]) + 1, "url": url, "bytes": 0}
        history["requests"].append(event)
        ledger.write_text(json.dumps(history, indent=2, sort_keys=True) + "\n")
        started = time.monotonic()
        request = urllib.request.Request(url, headers={"User-Agent": "bounded-source-license-followup", "Accept": "application/vnd.github+json" if parsed.hostname == "api.github.com" else "*/*"})
        try:
            response = opener.open(request, timeout=20)
        except urllib.error.HTTPError as failure:
            response = failure
        try:
            body = bytearray()
            while True:
                if time.monotonic() - started > 60:
                    raise TimeoutError("60second transfer deadline")
                remaining = min(ONE_BODY - len(body), TOTAL_BYTES - history["body_bytes"])
                if remaining <= 0:
                    raise ValueError("finite HTTP body cap reached before EOF")
                part = response.read(min(65536, remaining))
                if not part:
                    break
                body.extend(part)
                event["bytes"] += len(part)
                history["body_bytes"] += len(part)
                if len(body) > ONE_BODY or history["body_bytes"] > TOTAL_BYTES:
                    raise ValueError("finite HTTP body budget exceeded")
            event.update({"HTTP": response.code, "sha256": hashlib.sha256(body).hexdigest(), "seconds": round(time.monotonic() - started, 3)})
            location = response.headers.get("Location")
            if response.code in (301, 302, 303, 307, 308) and location:
                event["location"] = urllib.parse.urljoin(url, location)
                url = event["location"]
            else:
                output.write_bytes(body)
                event["file"] = output.name
                return event
        finally:
            response.close()
            ledger.write_text(json.dumps(history, indent=2, sort_keys=True) + "\n")
    raise ValueError("redirect limit reached")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("output", type=Path)
    parser.add_argument("--ledger", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(fetch(args.url, args.output, args.ledger), sort_keys=True))
