# SSH Account-Compromise Detection in Splunk

[![detection-tests](https://github.com/Olaoluwa-byte/splunk-ssh-account-compromise-detection/actions/workflows/detection-tests.yml/badge.svg)](https://github.com/Olaoluwa-byte/splunk-ssh-account-compromise-detection/actions/workflows/detection-tests.yml)

Project 2 of the home lab. Extends [P1 SSH brute-force detection](https://github.com/Olaoluwa-byte/splunk-ssh-bruteforce-detection) from "someone is knocking" to "someone got in." A real remote attacker (Kali + Hydra over Tailscale) brute-forces UbuntuDesk; these detections catch the account compromise, not just the noise.

## Detections

| # | Detection | MITRE | Status |
|---|---|---|---|
| 1 | Success after failures | T1078 Valid Accounts | CI-tested |
| 2 | Remote + publickey/preauth failures | T1110 / T1133 | ✅ CI-tested |
| 3 | Distributed spraying (per-user across IPs) | T1110.003 | planned |

### 1. Success after failures (T1078)

Flags an **Accepted** SSH login from a source IP that produced **≥10 Failed** attempts in the preceding 10 minutes — the brute-force-then-in signature. Source: [`detections/success_after_failures.spl`](detections/success_after_failures.spl).

Tested against real Hydra attack data (12 failures + 1 success from one remote IP) plus a benign fat-finger login and a failures-only burst, so it fires on compromise and stays quiet on ordinary typos.

## CI

Every push/PR loads the fixtures into a digest-pinned Splunk 10.4.3 container and asserts detection behavior. Same harness as P1.5.

## Attacker environment

Kali 2023.3 (UTM on Apple Silicon) joined to a Tailscale tailnet as a distinct remote `src_ip`. Password auth on the target is scoped to the attacker's tailnet IP only (lab).
