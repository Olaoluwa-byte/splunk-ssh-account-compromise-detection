# SSH Account-Compromise Detection in Splunk

[![detection-tests](https://github.com/Olaoluwa-byte/splunk-ssh-account-compromise-detection/actions/workflows/detection-tests.yml/badge.svg)](https://github.com/Olaoluwa-byte/splunk-ssh-account-compromise-detection/actions/workflows/detection-tests.yml)

Project 2 of the home lab. Extends [P1 SSH brute-force detection](https://github.com/Olaoluwa-byte/splunk-ssh-bruteforce-detection) from *"someone is knocking"* to *"someone got in."* A real remote attacker — Kali + Hydra reaching the target over a Tailscale tailnet — brute-forces UbuntuDesk, and these detections catch the account compromise, not just the noise. Every detection is validated in CI against **real captured attack data**.

---

## Executive Summary

**Problem.** A brute-force *count* detection (P1) tells you an attack is happening. It doesn't tell you whether it worked, and it goes blind against key-only servers where failures never look like `Failed password`.

**What I built.** A distinct remote attacker (Kali 2023.3 in UTM on Apple Silicon, its own tailnet IP), a scoped lab exception so its traffic generates realistic telemetry, and two Splunk detections that close specific gaps P1 leaves open — each regression-tested on every push against genuine attack logs.

**What it catches.**

| Detection | Signal | The gap it closes |
|---|---|---|
| **Success after failures** (T1078) | An `Accepted` login from a source IP that just failed ≥10 times in 10 min | P1 sees only failures; it can't tell a *successful* compromise from ongoing noise |
| **Remote + key-only / preauth failures** (T1110) | ≥10 `Connection closed … [preauth]` events per source IP | Key-only SSH logs no `Failed password`, so P1 counts zero and stays silent |

**Outcome.** Two detections, both backed by real remote-attack data, both quiet on benign lookalikes (a two-typo login, an occasional dropped connection), and both unable to regress without failing CI.

### Results

| Detection | Real attack data | Fires on attack | Quiet on benign |
|---|---|---|---|
| Success after failures | 12 failures + 1 success from one Kali IP | 1 alert, critical, `failures_before_success=12` | 2-typo login → no alert |
| Key-only / preauth brute force | 12 real key-only preauth failures from Kali | 1 alert, high, `peak_preauth_failures=12` | occasional reconnect → no alert |

CI runs all cases on a digest-pinned Splunk 10.4.3 container on every push and PR: **5/5 passing.**

### Coverage & Limitations

| Gap | Status |
|---|---|
| Distributed spraying (many IPs, few attempts each) | Not covered in this release — needs a multi-host lab |
| Low-and-slow (<10 attempts per window) | Not covered — future longer-window (1–24h) aggregation |
| Single-attacker source | All data is from one Kali host; multi-source realism is future work |
| Regex-based parsing | Breaks if the OpenSSH log format changes — future CIM `Authentication` mapping |

### Framework Mapping

| Framework | Mapping |
|---|---|
| MITRE ATT&CK | T1078 Valid Accounts · T1110 Brute Force (incl. key-only/preauth) · T1133 External Remote Services |
| NIST SP 800-53 | AC-7 Unsuccessful Logon Attempts · AU-6 Audit Review · SI-4 System Monitoring · CM-3 (CI-gated detection changes) |
| CIS Controls v8 | 8.11 Audit Log Reviews · 13.1 Centralize Security Event Alerting · 6.8 Define/Maintain Role-Based Access |

---

## Appendix

<details>
<summary><b>A. Attacker environment</b></summary>

- **Attacker:** Kali Linux 2023.3 (arm64) in UTM on a MacBook Pro (M1 Pro). Hydra v9.5 for brute force. Pinned at 2023.3 — the old image's rolling upgrade 404s off the mirror, and the attack tooling is version-stable.
- **Network:** Kali joins the same Tailscale tailnet as the target and reaches it as a distinct remote `src_ip` (`100.65.108.123`), so attacks arrive as genuine remote traffic rather than localhost.
- **Target:** UbuntuDesk (Ubuntu 24.04, Splunk Enterprise 10.4.3). Remote SSH is key-only; password auth is scoped to the attacker's tailnet IP only, so Hydra generates realistic `Failed password` events. Key-only preauth failures are produced by forcing publickey-only from a host with no valid key on the target.
- **Data:** `index=linux_auth`, `sourcetype=linux_secure`, monitoring `/var/log/auth.log`.

</details>

<details>
<summary><b>B. Detection 1 — success after failures (T1078)</b></summary>

Flags an `Accepted` SSH login from a `src_ip` with **≥10 failed attempts in the preceding 10 minutes** — the brute-force-then-in signature. Source: [`detections/success_after_failures.spl`](detections/success_after_failures.spl).

```spl
index=linux_auth sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex "(?<result>Failed|Accepted) password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+) port"
| where isnotnull(src_ip)
| sort 0 _time
| streamstats time_window=10m sum(eval(if(result=="Failed",1,0))) AS prior_failures dc(eval(if(result=="Failed",user,null()))) AS users_tried BY src_ip
| where result=="Accepted" AND prior_failures>=10
| stats max(prior_failures) AS failures_before_success max(users_tried) AS users_tried values(user) AS compromised_user min(_time) AS compromise_time BY src_ip
| eval mitre="T1078", technique="Valid Accounts", severity="critical"
| where failures_before_success >= 10
```

Tested against the real Hydra burst (12 failures) followed by a successful login from the same IP, plus a two-typo benign login and a failures-only burst — so it fires on compromise and stays quiet on ordinary typos.

</details>

<details>
<summary><b>C. Detection 2 — remote + key-only / preauth brute force (T1110)</b></summary>

Counts `Connection closed by authenticating user … [preauth]` events per `src_ip`. These are the failures a **key-only** attacker produces — no `Failed password` line, so P1's detection misses them entirely. Source: [`detections/preauth_bruteforce.spl`](detections/preauth_bruteforce.spl).

```spl
index=linux_auth sourcetype=linux_secure "Connection closed by authenticating user" "[preauth]"
| rex "Connection closed by authenticating user (?<user>\S+) (?<src_ip>\S+) port"
| where isnotnull(src_ip)
| sort 0 _time
| streamstats time_window=5m count AS preauth_failures dc(user) AS users_tried BY src_ip
| where preauth_failures >= 10
| stats max(preauth_failures) AS peak_preauth_failures dc(user) AS users_targeted values(user) AS users min(_time) AS first_seen BY src_ip
| eval mitre="T1110", technique="Brute Force (key-only / preauth)", severity="high"
```

Tested against 12 real key-only brute-force attempts from Kali (publickey-only, no valid key on the target) plus benign client reconnects.

</details>

<details>
<summary><b>D. Detection-as-code CI</b></summary>

Every push and PR loads the fixtures into a digest-pinned **Splunk 10.4.3** container, runs each detection verbatim (only the index swapped), and asserts alert rows and fields. One harness ([`tests/run_tests.py`](tests/run_tests.py)) tests all detections; adding one is appending a suite entry.

- Runner `ubuntu-24.04`, `actions/checkout@v5`, per-run random masked password (no GitHub Secrets).
- Static fixtures are searched over all time (`latest_time=+10y`) so timezone/wall-clock never excludes them — the container runs UTC.
- Fixtures are real captured `auth.log` lines from the Kali attacks.

</details>

<details>
<summary><b>E. Reproduce it</b></summary>

Requires the P1 lab (Ubuntu 24.04 + Splunk `index=linux_auth`), plus a Kali attacker on the same tailnet.

```bash
# From Kali, a brute-force burst that fails (password auth scoped to this IP):
printf 'password\n123456\nadmin\nletmein\nqwerty\nabc123\npassw0rd\nwelcome\nmonkey\ndragon\nhunter2\nsunshine\n' > ~/passwords.txt
hydra -l <user> -P ~/passwords.txt -t 4 ssh://<target>

# A successful login after the burst (account-compromise signal, T1078):
ssh <user>@<target>   # correct password

# Key-only preauth failures (no Failed password -> T1110 detection):
for i in $(seq 1 12); do ssh -o PreferredAuthentications=publickey -o BatchMode=yes <user>@<target> true 2>/dev/null; done
```

Run the detections over the last 15 minutes, or run the CI suite locally:

```bash
export SPLUNK_PASSWORD='<8+ chars>'
./tests/start_splunk.sh && python3 tests/run_tests.py
docker rm -f splunk-ci
```

</details>

<details>
<summary><b>F. Next steps</b></summary>

- Low-and-slow detection over 1–24h windows.
- Map to the CIM `Authentication` data model and convert to `tstats`.

</details>

---

**Samson Amosu** — Security Engineer (detection engineering, Splunk ES) · [LinkedIn](https://www.linkedin.com/in/samson-amosu) · [GitHub](https://github.com/Olaoluwa-byte)
