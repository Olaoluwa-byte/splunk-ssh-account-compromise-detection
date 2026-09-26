#!/usr/bin/env python3
"""P2 detection #1: success-after-failures (T1078). Load fixtures into a throwaway
Splunk, run the detection, assert alert rows and fields."""
import base64, json, os, ssl, subprocess, sys, time, urllib.parse, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTAINER = os.environ.get("SPLUNK_CONTAINER", "splunk-ci")
API = os.environ.get("SPLUNK_API", "https://localhost:18089")
PW = os.environ["SPLUNK_PASSWORD"]
DETECTION = os.path.join(ROOT, "detections", "success_after_failures.spl")
PROD_INDEX = "index=linux_auth"

# fixture, test index, raw lines, expected alert rows, (labels or None)
CASES = [
    ("attack_then_success.log", "t_compromise", 13, 1,
     {"failures_before_success": "12", "severity": "critical", "compromised_user": "yuji"}),
    ("benign_login.log",        "t_benign",      3, 0, None),
    ("failures_only.log",       "t_failonly",   12, 0, None),
]

CTX = ssl._create_unverified_context()

def api(path, **data):
    req = urllib.request.Request(API + path, data=urllib.parse.urlencode(data).encode())
    tok = base64.b64encode(f"admin:{PW}".encode()).decode()
    req.add_header("Authorization", "Basic " + tok)
    with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
        return r.read().decode()

def search(spl):
    spl = spl.strip()
    if not spl.startswith("|"):
        spl = "search " + spl
    body = api("/services/search/jobs/export", search=spl, output_mode="json",
               earliest_time="0", latest_time="+10y")
    return [json.loads(l)["result"] for l in body.splitlines()
            if l.strip() and "result" in json.loads(l)]

def cli(*args):
    r = subprocess.run(["docker", "exec", "-u", "splunk", CONTAINER, "/opt/splunk/bin/splunk",
                        *args, "-auth", f"admin:{PW}"], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr, sep="\n")
        raise AssertionError(f"splunk {' '.join(args)} failed ({r.returncode})")

def ingest(fixture, index, expected):
    src = os.path.join(ROOT, "tests", "fixtures", fixture)
    subprocess.run(["docker", "cp", src, f"{CONTAINER}:/tmp/{fixture}"], check=True)
    cli("add", "index", index)
    cli("add", "oneshot", f"/tmp/{fixture}", "-index", index, "-sourcetype", "linux_secure")
    for _ in range(60):
        n = int(search(f"| tstats count where index={index}")[0]["count"])
        if n == expected:
            return
        time.sleep(2)
    raise AssertionError(f"{fixture}: indexed {n}, expected {expected}")

def main():
    spl = open(DETECTION).read().strip()
    assert PROD_INDEX in spl, f"detection must reference {PROD_INDEX}"
    failures = 0
    for fixture, index, raw, alerts, labels in CASES:
        name = fixture.removesuffix(".log")
        try:
            ingest(fixture, index, raw)
            rows = search(spl.replace(PROD_INDEX, f"index={index}"))
            assert len(rows) == alerts, f"alert rows {len(rows)}, expected {alerts}"
            if labels:
                got = {k: rows[0].get(k) for k in labels}
                assert got == labels, f"fields {got}, expected {labels}"
            extra = f" failures_before_success={rows[0]['failures_before_success']}" if alerts else ""
            print(f"PASS {name}: alert_rows={len(rows)}{extra}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {name}: {e}")
    sys.exit(1 if failures else 0)

if __name__ == "__main__":
    main()
