# CerberusAI — Live-Fire Lab

Two ways to watch the triage engine work on a live stream. Start with the Lite
path (30 seconds, no Docker) to confirm the pipeline, then graduate to the real
Wazuh SIEM.

---

## Tier 1 — Lite pipeline (no Docker, no SIEM)

Proves the full **stream → triage → structured output** loop immediately. Only
needs your API key.

```bash
$env:ANTHROPIC_API_KEY = "sk-ant-..."
python lab/lite_pipeline.py
```

You'll see benign events score low and the brute-force burst / SQL-injection score
high, with results also appended to `outputs/live_triage.jsonl`. This is the same
`engine.triage()` the real SIEM path uses — only the *source* of the logs differs.

---

## Tier 2 — Real Wazuh SIEM

Architecture (all correct, unlike the single-container sketch):

```
attacker ──SSH brute force──► target (sshd + Wazuh AGENT)
                                   │ forwards /var/log/auth.log
                                   ▼
                              wazuh.manager ──► wazuh.indexer (wazuh-alerts-*)
                                                       ▲
                                   wazuh_poller.py ────┘  reads new alerts,
                                                          calls engine.triage()
```

> **Why the poller reads the *indexer*, not the manager API:** Wazuh alerts are
> stored in the indexer (OpenSearch, port 9200). The Manager API (55000) only
> serves agents/rules/config. Polling the manager for "alerts" returns nothing —
> a common mistake.

### Requirements (be realistic)

- Docker Desktop with **WSL2 backend**, ≥ 4 GB RAM free for the stack.
- The indexer needs `vm.max_map_count=262144`. In PowerShell:
  ```bash
  wsl -d docker-desktop sysctl -w vm.max_map_count=262144
  ```
  (Re-run after a Docker Desktop restart, or set it permanently in `.wslconfig`.)

### Step 1 — Bring up the official Wazuh single-node stack

Don't hand-roll Wazuh's deployment (certs, 3 services) — use the maintained repo:

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator   # one-time certs
docker compose up -d
```

Wait ~2–3 min, then confirm the dashboard at https://localhost (default login
`admin` / `SecretPassword`). If the indexer container restarts, it's almost always
`vm.max_map_count` — see above.

### Step 2 — Add the target + attacker (this repo's overlay)

From that same `wazuh-docker/single-node` directory, merge in our overlay:

```bash
docker compose -f docker-compose.yml -f C:/dev/Claude/cerberus-ai/lab/attack-lab.yml up -d --build
```

This builds the `target` (sshd + a real Wazuh agent) and starts the `attacker`.
Within a minute the agent enrolls and failed logins begin flowing. Verify alerts
exist:

```bash
curl -sk -u admin:SecretPassword "https://localhost:9200/wazuh-alerts-*/_count"
```

### Step 3 — Run the CerberusAI poller

Back in this repo, with your key set:

```bash
$env:ANTHROPIC_API_KEY = "sk-ant-..."
python lab/wazuh_poller.py
```

Each new Wazuh alert (rule level ≥ 7) gets triaged and written to
`outputs/live_triage.jsonl`. You now have a real SIEM detection being enriched by
your MCP engine in real time.

### Teardown

```bash
docker compose -f docker-compose.yml -f C:/dev/Claude/cerberus-ai/lab/attack-lab.yml down -v
```

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| indexer container keeps restarting | `vm.max_map_count` not set (Step 0) |
| poller: connection refused on 9200 | indexer still starting, or wrong `INDEXER_URL` |
| poller: 401 | indexer creds changed — set `INDEXER_USER` / `INDEXER_PASS` env |
| agent won't enroll: "Agent version must be lower or equal to manager" | agent newer than manager. The target Dockerfile pins `wazuh-agent=4.9.2-1` to match the manager tag — keep them equal. |
| agent won't enroll: "Duplicate agent name: target-host" | a stale registration from a previous `target` container. Remove it: `docker exec single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -r <id>` then restart the target. (Recreating the target gives it a fresh identity but the manager remembers the old name.) |
| auth.log has "Failed password" but no Wazuh alerts | two container gotchas the entrypoint fixes: (1) stock rsyslog leaves `/dev/log` off (no systemd), so sshd events vanish; (2) the stock agent config doesn't monitor `/var/log/auth.log`. Both are handled in `target/entrypoint.sh`. |
| individual alerts triage LOW even for a burst | expected — a single failed login *is* low. Wazuh correlates them into a level-10 "Multiple failed logins" alert; the poller enriches triage with the rule level/description so correlated alerts score higher. Point the poller at `MIN_LEVEL=10` to focus on correlated events. |
| `full_log` empty on some alerts | poller falls back to serializing `data`; not all rules carry a raw line |

This lab is not runtime-verified end-to-end in the environment it was authored in
(no running Docker / API key there). The topology and API calls are correct; treat
the first bring-up as a checklist and use the table above if a step sticks.
