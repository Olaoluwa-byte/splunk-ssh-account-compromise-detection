#!/usr/bin/env python3
"""P2 detection suite. Load fixtures into a throwaway Splunk, run each detection,
assert alert rows and fields. Add a detection by appending to SUITES."""
import base64, json, os, ssl, subprocess, sys, time, urllib.parse, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTAINER = os.environ.get("SPLUNK_CONTAINER", "splunk-ci")
API = os.environ.get("SPLUNK_API", "https://localhost:18089")
PW = os.environ["SPLUNK_PASSWORD"]
PROD_INDEX = "index=linux_auth"

# Each suite: a detection SPL and its cases.
# case = (fixture, test_index, raw_lines, expected_alert_rows, labels-or-None)
SUITES = [
    {
        "detection": "success_after_failures.spl",
        "cases": [
            ("attack_then_success.log", "t_compromise", 13, 1,
             {"failures_before_success": "12", "severity": "critical", "compromised_user": "yuji"}),
            ("benign_login.log", "t_benign", 3, 0, None),
            ("failures_only.log", "t_failonly", 12, 0, None),
        ],
    },
    {
        "detection": "preauth_bruteforce.spl",
        "cases": [
            ("keyonly_bruteforce.log", "t_keyonly", 12, 1,
             {"peak_preauth_failures": "12", "severity": "high"}),
            ("benign_reconnects.log", "t_reconnect", 3, 0, None),
        ],
    },
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
               earliest_time="0", latest_time="+10y")  # static fixtures: search all time
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
    failures = 0
    for suite in SUITES:
        spl = open(os.path.join(ROOT, "detections", suite["detection"])).read().strip()
        assert PROD_INDEX in spl, f"{suite['detection']} must reference {PROD_INDEX}"
        for fixture, index, raw, alerts, labels in suite["cases"]:
            name = fixture.removesuffix(".log")
            try:
                ingest(fixture, index, raw)
                rows = search(spl.replace(PROD_INDEX, f"index={index}"))
                assert len(rows) == alerts, f"alert rows {len(rows)}, expected {alerts}"
                if labels:
                    got = {k: rows[0].get(k) for k in labels}
                    assert got == labels, f"fields {got}, expected {labels}"
                print(f"PASS [{suite['detection']}] {name}: alert_rows={len(rows)}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL [{suite['detection']}] {name}: {e}")
    sys.exit(1 if failures else 0)

if __name__ == "__main__":
    main()
