
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
