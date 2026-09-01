# CerberusAI — How It Works (Team Overview)

*A plain-English walkthrough of what we built, how we test it, and why it matters.*

---

## In one sentence

**CerberusAI is an AI security analyst that reads a security alert, investigates it on its own, and tells you "safe to ignore" or "escalate now" — with the reasoning and proof — so the SOC team isn't drowning in noise.**

---

## The problem we're solving

- A SIEM (the platform that collects security alerts — Splunk, Elastic, Wazuh, etc.) throws off **thousands of alerts a day**.
- **~90%+ are false alarms**, but a human analyst still has to look at each one to be sure.
- Result: **alert fatigue** — analysts burn out, and the one real attack gets missed in the flood.

CerberusAI does the **first-line investigation automatically**, so humans only see what actually matters.

---

## What it actually does (the flow)

When an alert comes in, CerberusAI runs the same loop a senior analyst would — but in seconds:

1. **Remembers** — "Have we seen this source before? What did we decide last time?"
2. **Investigates** — it queries the SIEM *itself*: how many failed logins, and critically, **did any succeed?**
3. **Checks the map** — "Is this a normal connection, or is a machine suddenly talking to something it has *never* talked to before?" (That's the signature of an attacker moving deeper into the network — *lateral movement*.)
4. **Decides** — **AUTO-CLOSE** (safe, handled) or **ESCALATE** (real, human needed) — with a plain-English summary, the attack path, and the evidence.

> **Important:** it is **100% read-only**. It looks and reasons, but never changes, blocks, or touches any system. That's a big deal for enterprise/government approval (nothing to break, easy to trust).

---

## The pieces (in plain English)

| Piece | What it is |
|---|---|
| **The Brain** (`agent.py`) | Does the investigation and makes the call. Uses read-only tools to gather facts before deciding. |
| **The Memory** (`cerberus_memory.db`) | A local database that *learns your environment* over time — which machines are which, who normally talks to whom, and every past verdict. It starts empty and fills itself. |
| **The Dashboard** (`localhost:8787`) | The screen analysts watch. Each incident shows the decision, the attack path, the attacker's objective, and the proof timeline. |

**Why the memory is the moat:** the longer it runs in a customer's network, the more it knows *that specific network* — something a generic competitor can't copy. It's also built to survive real-world messiness: it keys on **stable machine names**, not IP addresses (IPs change constantly in the cloud / on Wi-Fi, and a naive tool would "forget" everything each time).

---

## How we test it (the lab)

We don't attack a real company. We built a **miniature fake network on one laptop** using **Docker** (lightweight throwaway "pretend computers" called containers). It has all the real moving parts:

```
   [ Attacker ]  ── keeps trying to break in over SSH ──►  [ Victim machines ]
                                                                   │  they report what happened
                                                                   ▼
                                                            [ Wazuh SIEM ]  ── raises alerts
                                                                   │
                                                                   ▼
                                                     [ CerberusAI ]  ── investigates → verdict
                                                                   │
                                                                   ▼
                                                     [ Dashboard @ localhost:8787 ]
```

- **The SIEM** = **Wazuh** (free, open-source, and genuinely used by enterprises).
- **Two victim machines**: `target-host` (a normal server) and `secure-db` (a stand-in for a **critical production database**).
- **The attacker** = a container that continuously tries to guess SSH passwords against both.

So it's a **real attack → real SIEM alerts → real AI investigation → verdict on screen**. The reasoning is not scripted or faked.

> **"Is this only for containers?"** No. Containers are just the cheap simulator. The exact same setup works for laptops, physical servers, firewalls, network switches, and cloud VMs — anything that sends logs to the SIEM. To CerberusAI it's all just "an asset that generated an alert."

---

## What a demo looks like (the money shot)

Two incidents, side by side, that look almost identical at the log level but get **opposite verdicts** — because CerberusAI understands *context*, not just keywords:

| Incident | What happened | Verdict |
|---|---|---|
| `app-worker-02 → target-host` | Brute-force against a machine it **normally** talks to. 246 failed logins, **zero succeeded**, matches past behavior. | **AUTO-CLOSE (2/10)** — safe, analyst never has to look. |
| `prod-web-01 → secure-db` | The *same* brute-force, but against a **critical database it has NEVER contacted before**. | **ESCALATE (8/10)** — unprecedented jump onto a critical asset = possible lateral movement. Human needed now. |

The killer detail: it escalates the second one **even though no login succeeded** — it catches the attacker's *intent* from the change in the network map, before the breach completes. And it never fabricates a breach that didn't happen (no hallucinated conclusions).

---

## Why it matters (the pitch in four lines)

1. **Cuts alert volume & analyst hours** — it auto-closes the noise, with evidence.
2. **Catches lateral movement early** — by knowing the network map, not just reading logs.
3. **Read-only = easy to approve** — no risk to the customer's systems.
4. **Learns each network over time** — so it gets more valuable the longer it runs (and harder to rip out).

---

## Current status

- ✅ Built and working: the brain, the self-growing memory, the dashboard, and the two-incident lateral-movement demo.
- ✅ Dashboard is live at **http://localhost:8787**.
- 🔄 Runs against the live test lab (Wazuh + attacker + two victim machines) on the dev laptop.

*This is an MVP prototype — the mechanism, the memory, and the executive-level reporting are all real. Next step is a recorded walkthrough for advisors/buyers.*
