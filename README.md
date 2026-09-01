# CerberusAI

**An open-source, read-only agentic SOC analyst.** Point it at your SIEM and it investigates
alerts on its own — querying the SIEM, checking what's normal for your network, and returning a
decision (**auto-close** or **escalate**) with plain-English reasoning and evidence. It exists to
kill alert fatigue: let the machine clear the noise so your analysts only see what matters.

> Not a lab or a simulator. You connect it to **your own** SIEM and it starts working.

---

## ⚠️ Read this first (what it does and doesn't do)

- **Read-only.** CerberusAI only *reads* from your SIEM and reasons about alerts. It never writes
  to, blocks, quarantines, patches, or reconfigures anything — not your SIEM, not your hosts, not
  your network gear. There is deliberately **no** switch/firewall automation.
- **It sends alert text to the Anthropic API.** To investigate an alert, the relevant alert text
  is sent to Anthropic's Claude API using **your own API key**. That is the only thing that leaves
  your environment, and it goes nowhere else. If sending alert data to a third-party LLM needs
  review in your org, review it before deploying.
- **No telemetry, no phone-home.** CerberusAI collects nothing and sends nothing to the project.
- **You bring your own key.** Get one at [console.anthropic.com](https://console.anthropic.com/settings/keys).
  API usage is billed to your key.

---

## Quick start (Docker — recommended)

```bash
git clone <your-repo-url> cerberus-ai && cd cerberus-ai
docker compose up -d
```

Open **http://localhost:8787** and complete the setup wizard (2 fields' worth). That's it — no
config files, no editing code.

## Quick start (local Python)

```bash
pip install -r requirements.txt
python -m uvicorn dashboard:app --port 8787
```

Then open **http://localhost:8787**.

---

## The setup wizard (all in the browser)

1. **Connect your SIEM** — pick your platform, enter the URL + credentials, click **Test
   Connection**. Read-only.
2. **Connect the AI engine** — paste your Anthropic API key, pick a model, click **Verify Key**.
3. **Initialize** — CerberusAI writes its config, starts the engine, and drops you into the live
   operations console.

Everything after that is automatic: as your SIEM raises alerts, CerberusAI investigates each new
source and posts a verdict to the dashboard.

---

## Supported SIEMs

CerberusAI talks to SIEMs through a small **adapter** layer, so the brain is SIEM-agnostic.

| SIEM | Status |
|------|--------|
| **Wazuh** | ✅ Supported (tested) |
| **Elastic Security** | ✅ Supported (OpenSearch adapter; may need field-map tweaks) |
| **Security Onion** | ✅ Supported (OpenSearch adapter; may need field-map tweaks) |
| Splunk, Microsoft Sentinel, QRadar, … | 🛣️ Roadmap — **contributions welcome** |

**Using a SIEM we don't support yet?** Add an adapter in [`siem/`](siem/) — implement three
methods (`test_connection`, `list_recent_sources`, `query_source_activity`) and the whole engine
works against it. The brain never changes.

Field mappings for non-Wazuh OpenSearch SIEMs can be adjusted in `config.json` under `siem.fields`.

---

## How it works

```
Your SIEM ──► CerberusAI agent (read-only tools)          ┌─ learns your network over time
   alerts       recall memory · query SIEM · drift check  │  (assets, who-talks-to-whom, verdicts)
                          │                                │  keyed on stable hostnames, so it
                          ▼                                │  survives DHCP / cloud IP churn
              grounded verdict + DECISION  ◄───────────────┘
              (auto-close / escalate)
                          │
                          ▼
              Operations console @ localhost:8787
```

- **Investigates, doesn't advise.** It runs the checks itself and returns a conclusion, not a
  to-do list.
- **Catches lateral movement.** It learns normal connection patterns; a machine suddenly reaching
  a host it has never touched (especially a critical one) is escalated — even before any login
  succeeds.
- **Grounded.** Every verdict cites the evidence it actually retrieved. It abstains and escalates
  rather than inventing a conclusion.
- **Learns your environment.** A local SQLite "memory" starts empty and fills itself. The longer
  it runs, the smarter it is about *your* network.

---

## Configuration reference

Written by the wizard to `config.json` (git-ignored — it holds secrets). Data lives on the
`/data` volume in Docker (`CERBERUS_CONFIG`, `CERBERUS_MEMORY_DB`, `CERBERUS_VERDICTS` override paths).

---

## Contributing

The highest-value contribution is a **new SIEM adapter** — see [`siem/base.py`](siem/base.py) for
the interface. Bug reports and redacted edge-case verdicts are welcome as issues.

## License

Add your license before publishing (e.g. Apache-2.0 or MIT).
