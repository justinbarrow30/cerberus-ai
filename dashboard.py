"""CerberusAI Operations Platform — the product UI over the autonomous agent.

Reads the agent's verdicts (outputs/verdicts.jsonl) and renders an enterprise-grade
SOC console: a live incident stream on the left, and the selected incident's
automated investigation timeline + evidence + attack path on the right.

Run:  python -m uvicorn dashboard:app --port 8787   (then open http://localhost:8787)
Feed it:  python lab/seed_dashboard.py   OR   python agent_poller.py
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

import llm
from auth import COOKIE_NAME, SESSION_TTL, Auth
from config import is_configured, load_config, save_config
from siem import get_adapter

APP_DIR = Path(__file__).resolve().parent
VERDICTS = Path(os.environ.get("CERBERUS_VERDICTS", APP_DIR / "outputs" / "verdicts.jsonl"))

app = FastAPI(title="CerberusAI Operations Platform")
_auth = Auth()

# --- ACAS-style access gate: log in to reach the console ---------------------
_PUBLIC = {"/login", "/api/login"}
_SETUP = {"/setup", "/api/test-connection", "/api/test-llm", "/api/save-config"}


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    path = request.url.path
    user = _auth.session_user(request.cookies.get(COOKIE_NAME))
    setup_open = not _auth.any_user_exists()   # first run: setup is reachable without a login
    if path in _PUBLIC:
        allowed = True
    elif path in _SETUP:
        allowed = setup_open or (user is not None and user.get("role") == "admin")
    else:
        allowed = user is not None
    if allowed:
        if user:
            request.state.user = user
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse({"error": "authentication required"}, status_code=401)
    return RedirectResponse("/setup" if setup_open else "/login")


def _current_user(request: Request) -> dict | None:
    return _auth.session_user(request.cookies.get(COOKIE_NAME))


# --- Self-launch: the poller runs as a child process once configured ---------
_poller_proc: subprocess.Popen | None = None


def ensure_poller_running() -> None:
    """Start agent_poller.py as a background subprocess if configured and not
    already running. This is what makes the tool self-launch after the wizard —
    the user never touches a terminal."""
    global _poller_proc
    if not is_configured():
        return
    if _poller_proc is not None and _poller_proc.poll() is None:
        return  # already running
    _poller_proc = subprocess.Popen(
        [sys.executable, str(APP_DIR / "agent_poller.py")],
        cwd=str(APP_DIR),
    )


@app.on_event("startup")
async def _on_startup() -> None:
    ensure_poller_running()  # returning users with a saved config resume immediately

# ---------------------------------------------------------------------------
# Executive Translation Layer.
# The agent stores audit-grade, technical ground truth. This layer turns that
# telemetry into plain English a security executive reads in five seconds:
# what happened, what the attacker wanted, how we proved they failed. The raw
# record is untouched — this is presentation only.
# ---------------------------------------------------------------------------

FRIENDLY = {   # stable asset id -> human name a leader recognizes
    "prod-web-01": "Production Web Server",
    "app-worker-02": "App Worker Node",
    "target-host": "Application Host",
    "secure-db": "Core Production Database",
}

# MITRE technique -> (plain title, one-line explanation of the adversary's intent)
MITRE_HUMAN = {
    "T1110": ("Password guessing", "Rapidly tried many username & password combinations, hoping one would let them in."),
    "T1078": ("Trying valid accounts", "Attempted to log in as real users to blend in with normal traffic."),
    "T1021": ("Remote access attempt", "Tried to open a remote command session on the machine."),
    "T1589": ("Harvesting usernames", "Probed for which account names exist to target next."),
}


def _friendly(name: str) -> str:
    return FRIENDLY.get(name, name)


def _max_int(text: str, pattern: str):
    """Largest match — a source is queried over several windows (60m→0, 24h→246);
    the meaningful figure is the sustained maximum, not whichever appears first."""
    vals = [int(s) for v in re.findall(pattern, text) if (s := v.replace(",", "")).isdigit()]
    return max(vals) if vals else None


def executive(r: dict) -> dict:
    """Derive the executive-facing narrative from the agent's raw verdict."""
    blob = " ".join(s.get("detail", "") for s in r.get("trace", [])) + " || " + " ".join(r.get("evidence", []))
    disp = r.get("disposition")
    unprec = bool(r.get("unprecedented_edge"))
    src, tgt = _friendly(r.get("source", "")), _friendly(r.get("target", ""))
    failed = _max_int(blob, r"([\d,]+)\s*failed")
    compromised = bool(r.get("compromise_confirmed"))   # authoritative agent field, not prose
    window = "the last 24 hours" if "1440" in blob else "the last hour"
    seen_times = _max_int(blob, r"seen\s*(\d+)\s*x") or _max_int(blob, r"'auto_close':\s*(\d+)")

    if disp == "escalate":
        headline = (f"{src} tried to reach the {tgt} — a critical system it has never touched before. "
                    f"A machine suddenly reaching a system it has no business touching is a classic sign "
                    f"of an attacker moving deeper into the network. Cerberus flagged it for a human.")
        impact = "Routed to a senior analyst with the full attack story already assembled."
    elif disp == "auto_close":
        headline = (f"Cerberus handled this one on its own — no analyst needed. It confirmed the {src}'s "
                    f"activity was harmless and expected, with no sign anyone got in, and closed the case.")
        impact = "~30 minutes of manual triage avoided. Your team never had to touch it."
    else:
        headline = f"Cerberus is keeping a passive watch on the {src}. Not urgent, but tracked."
        impact = "Held for monitoring."

    objective, seen = [], set()
    for c in r.get("mitre_techniques", []):
        m = re.match(r"(T\d+)", c)
        key = m.group(1) if m else c
        if key in seen or key not in MITRE_HUMAN:
            continue
        seen.add(key)
        objective.append({"code": key, "title": MITRE_HUMAN[key][0], "detail": MITRE_HUMAN[key][1]})

    vol = f"{failed:,} login attempts" if failed else "the login activity"
    if compromised:
        s1 = f"Reviewed {window}: {vol} — and at least one SUCCEEDED. A break-in is likely; this needs a human now."
    elif failed:
        s1 = f"Reviewed {window}: {failed:,} login attempts, and every single one FAILED. The attacker never got in."
    else:
        s1 = f"Reviewed {window} — found no successful logins. No sign anyone got in."
    if unprec:
        s2 = (f"The {src} has never connected to the {tgt} before. This brand-new, unexpected path "
              f"is the fingerprint of an attacker spreading to new systems.")
    else:
        cnt = f" (seen {seen_times} times before)" if seen_times else ""
        s2 = f"The {src} has used this exact path before{cnt}. Nothing new — the attacker is not spreading."
    s3 = {"auto_close": "Confirmed harmless, expected activity. Case closed automatically.",
          "escalate": "Dangerous pattern on a critical system. Escalated for a human decision.",
          "monitor": "Low priority. Kept under watch."}.get(disp, "")

    timeline = [
        {"q": "Did anyone actually break in?", "a": s1, "good": not compromised},
        {"q": "Is the attacker spreading to new systems?", "a": s2, "good": not unprec},
        {"q": "Cerberus' decision", "a": s3, "good": disp == "auto_close"},
    ]
    return {"source_friendly": src, "target_friendly": tgt, "headline": headline,
            "impact": impact, "objective": objective, "exec_timeline": timeline}


def load_verdicts() -> list[dict]:
    if not VERDICTS.exists():
        return []
    rows: list[dict] = []
    for line in VERDICTS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    rows.reverse()
    for r in rows:
        r["exec"] = executive(r)
    return rows


@app.get("/api/verdicts")
def api_verdicts() -> JSONResponse:
    rows = load_verdicts()
    return JSONResponse({
        "total": len(rows),
        "escalate": sum(1 for r in rows if r.get("disposition") == "escalate"),
        "auto_close": sum(1 for r in rows if r.get("disposition") == "auto_close"),
        "records": rows,
    })


@app.get("/")
def index():
    # First run (no config.json) -> send the user to the visual setup wizard.
    if not is_configured():
        return RedirectResponse("/setup")
    return HTMLResponse(PAGE)


@app.get("/setup", response_class=HTMLResponse)
def setup_page() -> str:
    # first_run gates the "create admin" step; configured hides SIEM/AI when this
    # is an existing deployment just adding the login.
    page = SETUP_PAGE.replace("__FIRST_RUN__", "true" if not _auth.any_user_exists() else "false")
    return page.replace("__CONFIGURED__", "true" if is_configured() else "false")


@app.post("/api/test-connection")
async def api_test_connection(req: Request) -> JSONResponse:
    """Read-only SIEM reachability + auth check for the wizard's Test button."""
    body = await req.json()
    try:
        adapter = get_adapter({"siem": body})
    except ValueError as e:
        return JSONResponse({"ok": False, "message": str(e)})
    try:
        ok, message = await adapter.test_connection()
    except Exception as e:  # never let a bad input crash the wizard
        ok, message = False, f"Connection error: {e}"
    return JSONResponse({"ok": ok, "message": message})


@app.post("/api/test-llm")
async def api_test_llm(req: Request) -> JSONResponse:
    """Verify the user's chosen LLM (any provider) with a tiny round-trip."""
    ai = (await req.json()).get("ai", {})
    try:
        ok, message = await llm.test_llm(ai)
    except Exception as e:
        ok, message = False, f"{type(e).__name__}: {e}"
    return JSONResponse({"ok": ok, "message": message})


@app.post("/api/save-config")
async def api_save_config(req: Request) -> JSONResponse:
    """Persist config.json and self-launch the engine — the last wizard step."""
    body = await req.json()
    existing = load_config() if is_configured() else {}
    cfg = {}
    # Only overwrite a section if the wizard actually sent it — so an existing
    # deployment can add the login step without re-entering SIEM/AI.
    if body.get("siem"):
        siem = body["siem"]
        cfg["siem"] = {
            "provider": siem.get("provider", "opensearch"),
            "url": siem.get("url", "").rstrip("/"),
            "user": siem.get("user", ""),
            "password": siem.get("password", ""),
            "verify_tls": bool(siem.get("verify_tls", False)),
            "index": siem.get("index", "wazuh-alerts-*"),
            "min_level": int(siem.get("min_level", 5)),
        }
    else:
        cfg["siem"] = existing.get("siem", {})
    if body.get("ai"):
        ai = body["ai"]
        cfg["ai"] = {
            "provider": ai.get("provider", "anthropic"),
            "model": (ai.get("model") or "").strip(),
            "api_key": (ai.get("api_key") or "").strip(),
            "endpoint": (ai.get("endpoint") or "").strip(),
            "api_version": (ai.get("api_version") or "").strip(),
        }
    else:
        cfg["ai"] = existing.get("ai", {})
    save_config(cfg)
    resp = JSONResponse({"ok": True})
    # First run: create the admin account and sign them straight in (ACAS-style).
    if not _auth.any_user_exists():
        admin = body.get("admin", {})
        ok, msg = _auth.create_user(admin.get("username", ""), admin.get("password", ""), role="admin")
        if not ok:
            return JSONResponse({"ok": False, "message": msg})
        token = _auth.start_session((admin.get("username") or "").strip())
        resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", max_age=SESSION_TTL)
    ensure_poller_running()
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page() -> str:
    return LOGIN_PAGE


@app.post("/api/login")
async def api_login(req: Request) -> JSONResponse:
    body = await req.json()
    username = (body.get("username") or "").strip()
    if _auth.verify(username, body.get("password") or ""):
        token = _auth.start_session(username)
        resp = JSONResponse({"ok": True})
        resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", max_age=SESSION_TTL)
        return resp
    return JSONResponse({"ok": False, "message": "Invalid username or password."})


@app.post("/api/logout")
async def api_logout(req: Request) -> JSONResponse:
    _auth.end_session(req.cookies.get(COOKIE_NAME))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE_NAME)
    return resp


@app.get("/api/me")
def api_me(req: Request) -> JSONResponse:
    return JSONResponse(_current_user(req) or {})


@app.get("/api/users")
def api_users(req: Request) -> JSONResponse:
    u = _current_user(req)
    if not u or u.get("role") != "admin":
        return JSONResponse({"error": "admin only"}, status_code=403)
    return JSONResponse({"users": _auth.list_users()})


@app.post("/api/users")
async def api_add_user(req: Request) -> JSONResponse:
    u = _current_user(req)
    if not u or u.get("role") != "admin":
        return JSONResponse({"error": "admin only"}, status_code=403)
    body = await req.json()
    ok, msg = _auth.create_user(body.get("username", ""), body.get("password", ""),
                                role=body.get("role", "analyst"))
    return JSONResponse({"ok": ok, "message": msg})


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CerberusAI Operations Platform</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700;800;900&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#FFFFFF; --bg2:#FAFAFB; --bar:#0A0C10; --onbar:#F4F5F7; --onbar-dim:#8A909C;
    --ink:#0A0C10; --body:#4A4F59; --faint:#9CA1AC; --line:#E5E7EC; --line2:#D6D9E0;
    --esc:#E11900; --esc-ink:#B31400; --ok:#0E7A46; --warn:#B06A00; --accent:#6366F1;
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;background:var(--bg);color:var(--ink);
    font-family:'Archivo',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    font-size:13px;-webkit-font-smoothing:antialiased;display:flex;flex-direction:column;height:100vh;
    letter-spacing:-0.01em}
  .mono{font-family:'IBM Plex Mono',ui-monospace,Consolas,monospace;letter-spacing:0}
  .lbl{font-size:10px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--faint)}
  .idx{font-family:'IBM Plex Mono',monospace;font-weight:600;color:var(--esc);margin-right:8px}

  /* ---- dark command bar ---- */
  header{display:flex;align-items:stretch;height:58px;background:var(--bar);color:var(--onbar);
    flex:0 0 auto;padding-left:22px}
  .wm{display:flex;align-items:center;font-weight:900;font-size:19px;letter-spacing:-0.03em}
  .wm span{color:var(--esc)}
  .unit{display:flex;align-items:center;margin-left:16px;padding-left:16px;border-left:1px solid #23262E;
    font-size:10.5px;font-weight:700;letter-spacing:.2em;color:var(--onbar-dim)}
  .spacer{flex:1}
  .readout{display:flex;flex-direction:column;justify-content:center;align-items:flex-end;
    padding:0 20px;border-left:1px solid #191C22;min-width:96px}
  .readout b{font-size:22px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
  .readout em{font-style:normal;font-size:9px;font-weight:700;letter-spacing:.14em;color:var(--onbar-dim);margin-top:5px}
  .readout.e b{color:#FF5A3C}
  .status{display:flex;align-items:center;gap:8px;padding:0 22px;background:#12151B;
    font-family:'IBM Plex Mono',monospace;font-size:10.5px;font-weight:600;letter-spacing:.1em;color:#4ADE80}
  .status i{width:7px;height:7px;border-radius:50%;background:#22C55E;display:inline-block;animation:ping 1.9s infinite}
  @keyframes ping{0%{box-shadow:0 0 0 0 rgba(34,197,94,.55)}70%{box-shadow:0 0 0 7px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}

  /* ---- body split ---- */
  main{flex:1;display:grid;grid-template-columns:minmax(360px,37%) 1fr;min-height:0}
  .col{min-height:0;display:flex;flex-direction:column}
  .col.stream{border-right:1px solid var(--line2);background:var(--bg2)}
  .secbar{display:flex;align-items:baseline;justify-content:space-between;padding:16px 20px 12px;
    border-bottom:1px solid var(--line)}
  .secbar .h{font-size:12px;font-weight:800;letter-spacing:.02em;text-transform:uppercase}
  .rows{overflow:auto}

  /* ---- queue rows (table-like, squared) ---- */
  .qrow{display:grid;grid-template-columns:96px 1fr;gap:4px 12px;padding:14px 20px;cursor:pointer;
    border-bottom:1px solid var(--line);border-left:3px solid transparent;position:relative;
    transition:transform .14s ease, box-shadow .14s ease, background .14s ease}
  .qrow:hover{background:#fff;transform:translateY(-1px);z-index:1;
    box-shadow:0 3px 12px rgba(15,23,42,.06), inset 0 0 0 1px rgba(99,102,241,.4)}
  .qrow.sel{background:#fff;border-left-color:var(--ink)}
  .qrow.sel.escalate{border-left-color:var(--esc)}
  .qdisp{grid-row:1;font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:700;letter-spacing:.05em;
    align-self:center;padding:4px 0;text-align:center;border:1px solid var(--line2);text-transform:uppercase}
  .qdisp.escalate{color:var(--esc);border-color:var(--esc)}
  .qdisp.auto_close{color:var(--ok);border-color:#BFE0CD}
  .qdisp.monitor{color:var(--warn);border-color:#EAD6AC}
  .qpath{grid-column:2;grid-row:1;font-size:14px;font-weight:700;align-self:center;letter-spacing:-0.02em}
  .qpath i{color:var(--faint);font-style:normal;margin:0 7px;font-weight:400}
  .qmeta{grid-column:2;grid-row:2;font-size:10.5px;color:var(--faint);font-weight:400;letter-spacing:.04em}

  /* ---- detail ---- */
  .detail{overflow:auto;padding:0 0 60px}
  .dhero{padding:26px 30px 22px;border-bottom:1px solid var(--line);display:flex;gap:24px;align-items:flex-start}
  .dhero .who{flex:1;min-width:0}
  .kdisp{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:700;letter-spacing:.14em;margin-bottom:12px}
  .kdisp.escalate{color:var(--esc)} .kdisp.auto_close{color:var(--ok)} .kdisp.monitor{color:var(--warn)}
  .entity{font-size:30px;font-weight:800;letter-spacing:-0.035em;line-height:1.05}
  .entity .arrow{color:var(--line2);font-weight:400;margin:0 10px}
  .entity .crit{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:700;letter-spacing:.08em;
    text-transform:uppercase;color:var(--esc);border:1px solid var(--esc);padding:2px 7px;margin-left:12px;
    vertical-align:middle;white-space:nowrap}
  .subline{margin-top:12px;font-size:11px;color:var(--body);font-weight:400;
    font-family:'IBM Plex Mono',monospace;letter-spacing:.05em}
  .subline b{color:var(--esc)}
  .scorewrap{flex:0 0 auto;padding-left:22px;border-left:1px solid var(--line);display:flex;flex-direction:column;align-items:center;gap:10px}
  /* premium radial threat gauge */
  .gauge{position:relative;width:120px;height:120px}
  .gauge svg{width:120px;height:120px;transform:rotate(-90deg)}
  .gauge .track{fill:none;stroke:#ECEEF2;stroke-width:3}
  .gauge .prog{fill:none;stroke-width:3;stroke-linecap:round;transition:stroke-dasharray .7s cubic-bezier(.4,0,.2,1)}
  .gauge.escalate .prog{stroke:var(--esc);filter:drop-shadow(0 0 4px rgba(225,25,0,.4))}
  .gauge.auto_close .prog{stroke:#64748B}
  .gauge.monitor .prog{stroke:var(--warn)}
  .gauge .gnum{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;line-height:.88}
  .gauge .gnum .n{font-size:45px;font-weight:900;letter-spacing:-0.04em}
  .gauge .gnum .d{font-size:12px;color:var(--faint);font-weight:700;margin-top:3px}
  .gauge.escalate .gnum{color:var(--esc)} .gauge.auto_close .gnum{color:#334155} .gauge.monitor .gnum{color:var(--warn)}
  .gcap{font-size:9px;font-weight:800;letter-spacing:.16em;color:var(--faint);text-transform:uppercase}
  .score{font-size:64px;font-weight:900;line-height:.85;letter-spacing:-0.05em;font-variant-numeric:tabular-nums}
  .score.escalate{color:var(--esc)} .score.auto_close{color:var(--ok)} .score.monitor{color:var(--warn)}
  .score em{font-size:20px;font-style:normal;color:var(--faint);font-weight:700}
  .scorewrap small{display:block;margin-top:8px;font-size:9.5px;font-weight:700;letter-spacing:.14em;color:var(--faint);text-transform:uppercase}

  .summary{padding:22px 30px;font-size:16px;line-height:1.5;font-weight:500;color:#1A1D24;
    border-bottom:1px solid var(--line);letter-spacing:-0.015em}

  .sect{padding:24px 30px;border-bottom:1px solid var(--line)}
  .sect h3{margin:0 0 16px;font-size:11px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;display:flex;align-items:center}

  /* attack path */
  .topo{display:flex;align-items:center}
  .node{display:flex;flex-direction:column;gap:6px;min-width:150px}
  .node .box{padding:12px 16px;border:1.5px solid var(--ink);font-family:'IBM Plex Mono',monospace;
    font-weight:600;font-size:14px;background:#fff}
  .node.crit .box{border-color:var(--esc);color:var(--esc)}
  .node small{font-size:9.5px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--faint)}
  .edge{flex:1;position:relative;height:0;border-top:2px solid var(--ink);margin:0 2px 22px}
  .edge.bad{border-top:2px dashed var(--esc)}
  .edge .etag{position:absolute;top:-11px;left:50%;transform:translateX(-50%);white-space:nowrap;background:var(--bg);
    padding:0 8px;font-family:'IBM Plex Mono',monospace;font-size:9.5px;font-weight:700;letter-spacing:.1em;color:var(--faint)}
  .edge.bad .etag{color:var(--esc)}
  .edge::after{content:"";position:absolute;right:-1px;top:-5px;border:5px solid transparent;border-left:8px solid var(--ink)}
  .edge.bad::after{border-left-color:var(--esc)}

  /* timeline */
  .tl{position:relative;padding-left:26px}
  .tl::before{content:"";position:absolute;left:4px;top:5px;bottom:5px;width:2px;background:var(--line2)}
  .step{position:relative;padding:0 0 18px}
  .step:last-child{padding-bottom:0}
  .step .pt{position:absolute;left:-26px;top:2px;width:10px;height:10px;background:var(--ink)}
  .step.memory .pt{background:#5B21B6} .step.siem .pt{background:#0A0C10}
  .step.drift .pt{background:var(--esc)} .step.verdict .pt{background:var(--ink);outline:3px solid #D6D9E0}
  .step .st{font-weight:700;font-size:13px;letter-spacing:-0.01em}
  .step.drift .st{color:var(--esc)}
  .step .sd{color:var(--body);font-size:12px;margin-top:3px;word-break:break-word;
    font-family:'IBM Plex Mono',monospace;letter-spacing:0;line-height:1.5}

  .ev{margin:0;padding:0;list-style:none}
  .ev li{padding:10px 0 10px 18px;border-bottom:1px solid var(--line);font-size:12.5px;color:#2A2E36;
    position:relative;line-height:1.5;font-weight:450}
  .ev li::before{content:"";position:absolute;left:0;top:16px;width:6px;height:6px;background:var(--ink)}
  .ev li:last-child{border-bottom:none}

  .chips{display:flex;flex-wrap:wrap;gap:8px}
  .chip{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:500;color:var(--ink);
    border:1px solid var(--line2);padding:5px 10px}

  .acts{margin:0;padding:0;list-style:none;counter-reset:a}
  .acts li{counter-increment:a;position:relative;padding:9px 0 9px 30px;font-size:13px;color:var(--body);
    border-bottom:1px solid var(--line);line-height:1.5;font-weight:450}
  .acts li:last-child{border-bottom:none}
  .acts li::before{content:counter(a,decimal-leading-zero);position:absolute;left:0;top:9px;
    font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:700;color:var(--esc)}

  .empty{color:var(--faint);text-align:center;padding:90px 20px;font-size:13px;font-weight:500}

  /* executive translation layer */
  .headline{padding:22px 30px 18px;font-size:17px;line-height:1.5;font-weight:600;color:var(--ink);
    letter-spacing:-0.015em}
  .impact{margin:0 30px 4px;padding:11px 15px;font-size:12.5px;font-weight:700;letter-spacing:.01em;
    display:flex;align-items:center;gap:9px;border:1px solid var(--line)}
  .impact.ok{color:var(--ok);background:#F1FAF5;border-color:#CDE9DA}
  .impact.esc{color:var(--esc);background:#FEF3F1;border-color:#F6CFC8}
  .impact.warn{color:var(--warn);background:#FBF6EC;border-color:#EAD9B4}
  .obj{display:flex;flex-direction:column;gap:16px}
  .objrow{display:flex;gap:14px;align-items:flex-start}
  .objrow .oc{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:700;color:var(--esc);
    border:1px solid var(--esc);padding:4px 8px;white-space:nowrap;margin-top:1px}
  .objrow .ot{font-size:15px;font-weight:700;letter-spacing:-0.01em}
  .objrow .od{font-size:13px;color:var(--body);margin-top:3px;line-height:1.5;font-weight:450}
  .step.good .pt{background:var(--ok)} .step.bad .pt{background:var(--esc)}
  .step.good .st,.step.bad .st{color:var(--ink)}
</style></head>
<body>
<header>
  <div class="wm">CERBERUS<span>/</span>AI</div>
  <div class="unit">SECURITY&nbsp;OPERATIONS</div>
  <div class="spacer"></div>
  <div class="readout e"><b id="s-esc">0</b><em>ESCALATED</em></div>
  <div class="readout"><b id="s-ok">0</b><em>AUTO-CLOSED</em></div>
  <div class="readout"><b id="s-total">0</b><em>ANALYZED</em></div>
  <div class="status"><i></i>OPERATIONAL</div>
  <div id="userbar" style="display:flex;align-items:center;gap:10px;margin-left:16px;padding-left:16px;border-left:1px solid #191C22"></div>
</header>

<main>
  <div class="col stream">
    <div class="secbar"><span class="h">Incident Queue</span><span class="lbl" id="qn"></span></div>
    <div class="rows" id="stream"><div class="empty">Awaiting verdicts —<br>run <span class="mono">lab/seed_dashboard.py</span></div></div>
  </div>
  <div class="col">
    <div class="secbar"><span class="h">Incident Detail</span></div>
    <div class="detail" id="detail"><div class="empty">Select an incident.</div></div>
  </div>
</main>

<script>
let DATA=[], SEL=null;
const esc=t=>{const d=document.createElement('div');d.textContent=(t==null?'':t);return d.innerHTML;};
const short=t=>{try{return new Date(t).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});}catch(e){return t;}};
const dispLabel=d=>({escalate:'ESCALATE',auto_close:'AUTO-CLOSE',monitor:'MONITOR'})[d]||d;

function renderStream(){
  const el=document.getElementById('stream');
  if(!DATA.length) return;
  document.getElementById('qn').textContent=DATA.length+' ACTIVE';
  el.innerHTML=DATA.map((r,i)=>`
    <div class="qrow ${esc(r.disposition)} ${SEL===i?'sel':''}" onclick="select(${i})">
      <div class="qdisp ${esc(r.disposition)}">${dispLabel(r.disposition)}</div>
      <div class="qpath">${esc(r.exec.source_friendly)}<i>→</i>${esc(r.exec.target_friendly)}</div>
      <div class="qmeta mono">${short(r.ts)} · ${esc(r.source)} → ${esc(r.target)}</div>
    </div>`).join('');
}

function renderDetail(){
  const el=document.getElementById('detail');
  if(SEL==null||!DATA[SEL]){el.innerHTML='<div class="empty">Select an incident.</div>';return;}
  const r=DATA[SEL], x=r.exec, bad=r.unprecedented_edge;
  const R=54, C=2*Math.PI*R, prog=(Math.max(0,Math.min(10,r.threat_score))/10)*C;
  const obj=(x.objective||[]).map(o=>`
    <div class="objrow"><div class="oc">${esc(o.code)}</div>
      <div><div class="ot">${esc(o.title)}</div><div class="od">${esc(o.detail)}</div></div></div>`).join('')
      || '<div class="od">No specific attacker technique identified.</div>';
  const tl=(x.exec_timeline||[]).map(s=>`
    <div class="step ${s.good?'good':'bad'}"><div class="pt"></div>
      <div class="st">${esc(s.q)}</div><div class="sd">${esc(s.a)}</div></div>`).join('');
  const acts=(r.recommended_actions||[]).map(a=>`<li>${esc(a)}</li>`).join('');
  const ic=r.disposition==='auto_close'?'ok':(r.disposition==='escalate'?'esc':'warn');
  el.innerHTML=`
    <div class="dhero">
      <div class="who">
        <div class="kdisp ${esc(r.disposition)}">${dispLabel(r.disposition)}</div>
        <div class="entity">${esc(x.source_friendly)}<span class="arrow">→</span>${esc(x.target_friendly)}${bad?'<span class="crit">critical asset</span>':''}</div>
        <div class="subline">${esc(r.source)} → ${esc(r.target)}${r.source_ip?('  //  IP '+esc(r.source_ip)):''}  //  CONFIDENCE ${Math.round((r.confidence||0)*100)}%</div>
      </div>
      <div class="scorewrap">
        <div class="gauge ${esc(r.disposition)}">
          <svg viewBox="0 0 120 120"><circle class="track" cx="60" cy="60" r="54"></circle><circle class="prog" cx="60" cy="60" r="54" style="stroke-dasharray:${prog} ${C}"></circle></svg>
          <div class="gnum"><span class="n">${esc(r.threat_score)}</span><span class="d">/10</span></div>
        </div>
        <div class="gcap">Threat Score</div>
      </div>
    </div>
    <div class="headline">${esc(x.headline)}</div>
    <div class="impact ${ic}">▪&nbsp;&nbsp;${esc(x.impact)}</div>
    <div class="sect"><h3><span class="idx">01</span>Attack Path</h3>
      <div class="topo">
        <div class="node"><div class="box">${esc(x.source_friendly)}</div><small>Source</small></div>
        <div class="edge ${bad?'bad':''}"><span class="etag">${bad?'NEVER SEEN BEFORE':'NORMAL / EXPECTED'}</span></div>
        <div class="node ${bad?'crit':''}"><div class="box">${esc(x.target_friendly)}</div><small>${bad?'Critical Asset':'Target'}</small></div>
      </div>
    </div>
    <div class="sect"><h3><span class="idx">02</span>What The Attacker Was Trying To Do</h3><div class="obj">${obj}</div></div>
    <div class="sect"><h3><span class="idx">03</span>How Cerberus Verified It</h3><div class="tl">${tl}</div></div>
    <div class="sect"><h3><span class="idx">04</span>What Happens Next</h3><ol class="acts">${acts}</ol></div>`;
}

window.select=i=>{SEL=i;renderStream();renderDetail();};

async function tick(){
  let d;try{d=await(await fetch('/api/verdicts')).json();}catch(e){return;}
  document.getElementById('s-esc').textContent=d.escalate;
  document.getElementById('s-ok').textContent=d.auto_close;
  document.getElementById('s-total').textContent=d.total;
  const changed=JSON.stringify(d.records.map(r=>r.ts))!==JSON.stringify(DATA.map(r=>r.ts));
  DATA=d.records;
  if(SEL==null&&DATA.length){SEL=0;}
  if(changed){renderStream();renderDetail();}
}
tick();setInterval(tick,5000);

// --- account / team (ACAS-style multi-user) ---
const HBTN="font:600 11.5px 'Archivo';color:#C8CCD4;background:#181B21;border:1px solid #2A2E36;border-radius:5px;padding:5px 10px;cursor:pointer;letter-spacing:.02em";
async function loadUser(){
  try{const me=await(await fetch('/api/me')).json(); if(!me.username) return;
    const admin=me.role==='admin'; const bar=document.getElementById('userbar');
    bar.innerHTML=`<span class="mono" style="font-size:11.5px;color:#8A909C;letter-spacing:.02em">${esc(me.username)}${admin?' · ADMIN':''}</span>`
      +(admin?`<button style="${HBTN}" onclick="openTeam()">Team</button>`:'')
      +`<button style="${HBTN}" onclick="logout()">Sign out</button>`;
  }catch(e){}
}
async function logout(){await fetch('/api/logout',{method:'POST'});window.location='/login';}
async function openTeam(){
  let list=[]; try{list=(await(await fetch('/api/users')).json()).users||[];}catch(e){}
  const rows=list.map(u=>`<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line);font-size:13px"><span class="mono">${esc(u.username)}</span><span style="color:var(--faint);font-size:11px;text-transform:uppercase;letter-spacing:.08em">${esc(u.role)}</span></div>`).join('');
  const ov=document.createElement('div');
  ov.style.cssText="position:fixed;inset:0;background:rgba(10,12,16,.55);display:grid;place-items:center;z-index:100";
  ov.innerHTML=`<div style="background:#fff;border:1px solid var(--line);border-radius:14px;width:400px;max-width:92vw;padding:24px;box-shadow:0 30px 70px rgba(15,23,42,.25)">
    <div style="font:800 16px 'Archivo';letter-spacing:-0.01em">Team</div>
    <div style="color:var(--faint);font-size:12.5px;margin:3px 0 16px">Analysts who can sign in to this console.</div>
    <div>${rows||'<div style="color:var(--faint);font-size:13px">No accounts yet.</div>'}</div>
    <div style="margin-top:18px;border-top:1px solid var(--line);padding-top:16px">
      <div class="lbl" style="margin-bottom:10px">Add analyst</div>
      <input id="nu" placeholder="username" class="mono" style="width:100%;padding:9px 11px;border:1px solid var(--line2);border-radius:8px;font-size:13px;margin-bottom:8px">
      <input id="np" type="password" placeholder="password (min 8 chars)" class="mono" style="width:100%;padding:9px 11px;border:1px solid var(--line2);border-radius:8px;font-size:13px">
      <div id="tmsg" class="mono" style="font-size:12px;min-height:16px;margin-top:8px"></div>
      <div style="display:flex;gap:10px;margin-top:6px">
        <button style="${HBTN};color:#fff;background:var(--ink);border-color:var(--ink);flex:1;padding:9px" onclick="addAnalyst(this)">Add analyst</button>
        <button style="${HBTN};flex:0 0 auto;padding:9px 14px" onclick="this.closest('[style*=fixed]').remove()">Close</button>
      </div>
    </div></div>`;
  ov.addEventListener('click',e=>{if(e.target===ov)ov.remove();});
  document.body.appendChild(ov);
}
async function addAnalyst(btn){
  const u=document.getElementById('nu').value.trim(),p=document.getElementById('np').value,m=document.getElementById('tmsg');
  m.style.color='var(--faint)';m.textContent='Adding…';btn.disabled=true;
  try{const r=await(await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})})).json();
    m.style.color=r.ok?'var(--ok)':'var(--esc)';m.textContent=(r.ok?'✓ ':'✕ ')+(r.message||'');
    if(r.ok){setTimeout(openTeamRefresh,700);}}catch(e){m.textContent='Error';}
  btn.disabled=false;
}
function openTeamRefresh(){const o=document.querySelector('[style*=fixed]');if(o)o.remove();openTeam();}
loadUser();
</script>
</body></html>"""


SETUP_PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CerberusAI — Setup</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700;800;900&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{--bg:#F7F8FA;--card:#FFFFFF;--bar:#0A0C10;--ink:#0A0C10;--body:#4A4F59;--faint:#9CA1AC;
    --line:#E5E7EC;--line2:#D6D9E0;--accent:#6366F1;--ok:#0E7A46;--esc:#E11900;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:'Archivo',system-ui,sans-serif;
    letter-spacing:-0.01em;min-height:100vh}
  .mono{font-family:'IBM Plex Mono',monospace;letter-spacing:0}
  header{background:var(--bar);color:#F4F5F7;height:58px;display:flex;align-items:center;padding:0 26px}
  .wm{font-weight:900;font-size:19px;letter-spacing:-0.03em}.wm span{color:var(--esc)}
  .unit{margin-left:16px;padding-left:16px;border-left:1px solid #23262E;font-size:10.5px;font-weight:700;
    letter-spacing:.2em;color:#8A909C}
  main{max-width:640px;margin:0 auto;padding:36px 24px 60px}
  h1{font-size:26px;font-weight:800;letter-spacing:-0.03em;margin:0 0 6px}
  .sub{color:var(--body);font-size:14px;margin:0 0 28px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px 24px;margin-bottom:18px}
  .step{display:flex;align-items:center;gap:10px;margin-bottom:18px}
  .step .n{font-family:'IBM Plex Mono',monospace;font-weight:700;font-size:12px;color:#fff;background:var(--ink);
    width:24px;height:24px;display:flex;align-items:center;justify-content:center;border-radius:6px}
  .step h2{font-size:15px;font-weight:800;margin:0}
  label{display:block;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);margin:14px 0 6px}
  input,select{width:100%;padding:10px 12px;border:1px solid var(--line2);border-radius:8px;font-size:14px;
    font-family:'IBM Plex Mono',monospace;background:#fff;color:var(--ink)}
  input:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.15)}
  .row{display:flex;gap:12px}.row>div{flex:1}
  .chk{display:flex;align-items:center;gap:8px;margin-top:14px;font-size:13px;color:var(--body)}
  .chk input{width:auto}
  .btn{margin-top:16px;padding:11px 16px;border:1px solid var(--ink);background:#fff;color:var(--ink);
    border-radius:8px;font-family:'Archivo';font-weight:700;font-size:13px;cursor:pointer;letter-spacing:.02em}
  .btn:hover{background:var(--ink);color:#fff}
  .btn:disabled{opacity:.4;cursor:not-allowed}
  .status{margin-top:12px;font-family:'IBM Plex Mono',monospace;font-size:12px;min-height:18px;display:none}
  .status.ok{display:block;color:var(--ok)} .status.err{display:block;color:var(--esc)}
  .status.wait{display:block;color:var(--faint)}
  .note{margin-top:14px;font-size:12px;line-height:1.5;color:var(--body);background:#F5F6FF;
    border:1px solid #E0E3FF;border-left:3px solid var(--accent);border-radius:6px;padding:10px 12px}
  .note b{color:var(--ink)}
  a{color:var(--accent);text-decoration:none;font-weight:600}
  .launch{width:100%;margin-top:6px;padding:15px;border:none;border-radius:10px;background:var(--ink);color:#fff;
    font-weight:800;font-size:15px;letter-spacing:.02em;cursor:pointer}
  .launch:hover{background:#1a1e26}.launch:disabled{background:#C9CDD5;cursor:not-allowed}
  .foot{text-align:center;color:var(--faint);font-size:11px;margin-top:16px}
</style></head>
<body>
<header><div class="wm">CERBERUS<span>/</span>AI</div><div class="unit">INITIAL&nbsp;SETUP</div></header>
<main>
  <h1>Connect CerberusAI to your environment</h1>
  <p class="sub">Two steps. Point it at your SIEM and your Anthropic key — no config files, no terminal. It's <b>read-only</b>: it reads alerts and reasons about them, and never changes your systems.</p>

  <div class="card">
    <div class="step"><span class="n">1</span><h2>Connect your SIEM (read-only)</h2></div>
    <label>SIEM Platform</label>
    <select id="provider" onchange="onProvider()">
      <option value="wazuh" data-index="wazuh-alerts-*">Wazuh Indexer (OpenSearch)</option>
      <option value="elastic" data-index=".alerts-security.alerts-*">Elastic Security</option>
      <option value="security-onion" data-index="*:so-*">Security Onion</option>
    </select>
    <label>Indexer / API Base URL</label>
    <input id="url" placeholder="https://your-siem-host:9200" autocomplete="off">
    <div class="row">
      <div><label>Username</label><input id="user" placeholder="admin" autocomplete="off"></div>
      <div><label>Password / API token</label><input id="password" type="password" autocomplete="off"></div>
    </div>
    <div class="row">
      <div><label>Alert Index Pattern</label><input id="index" class="mono"></div>
      <div><label>Min alert level</label><input id="minlevel" value="5" class="mono"></div>
    </div>
    <div class="chk"><input type="checkbox" id="verify"><label style="margin:0;text-transform:none;letter-spacing:0;font-weight:500;color:var(--body)">Verify TLS certificate (uncheck for self-signed / lab)</label></div>
    <button class="btn" onclick="testSiem()">Test Connection</button>
    <div class="status" id="s-siem"></div>
    <div class="note">Wazuh works out of the box. Elastic / Security Onion may need field-mapping tweaks in <span class="mono">config.json</span> — see the README. Using a SIEM we don't support yet? Add an adapter in <span class="mono">siem/</span>.</div>
  </div>

  <div class="card">
    <div class="step"><span class="n">2</span><h2>Connect your AI engine — bring your own LLM</h2></div>
    <label>AI Provider (use the model your org already approved)</label>
    <select id="aiprovider" onchange="onAi()">
      <option value="anthropic" data-model="claude-opus-5">Anthropic — Claude</option>
      <option value="openai" data-model="gpt-4o">OpenAI — ChatGPT</option>
      <option value="azure" data-model="gpt-4o">Microsoft Azure OpenAI (M365 / Copilot)</option>
      <option value="gemini" data-model="gemini-1.5-pro">Google — Gemini</option>
      <option value="deepseek" data-model="deepseek-chat">DeepSeek</option>
      <option value="custom" data-model="gpt-4o">Custom / OpenAI-compatible endpoint</option>
    </select>
    <label id="l-model">Model name</label>
    <input id="aimodel" class="mono">
    <div id="ep-wrap" style="display:none">
      <label id="l-ep">Endpoint URL</label>
      <input id="aiendpoint" class="mono" placeholder="https://your-resource.openai.azure.com" autocomplete="off">
    </div>
    <div id="ver-wrap" style="display:none">
      <label>Azure API Version</label>
      <input id="aiver" class="mono" value="2024-06-01" autocomplete="off">
    </div>
    <label>API Key</label>
    <input id="aikey" type="password" placeholder="paste your provider API key" autocomplete="off">
    <button class="btn" onclick="testLLM()">Verify AI Connection</button>
    <div class="status" id="s-key"></div>
    <div class="note"><b>Data notice:</b> To investigate an alert, CerberusAI sends the relevant alert text to the AI provider you pick, using <b>your</b> key. A <b>private</b> deployment (Azure in your tenant, or a self-hosted / gateway endpoint) keeps that data inside your environment; a public SaaS API (OpenAI, Gemini, DeepSeek) sends it to that vendor — one you've already vetted. It never writes to your systems. Note: tool-calling models (GPT-4, Claude, Gemini Pro class) give the best triage.</div>
  </div>

  <div class="card" id="admin-card">
    <div class="step"><span class="n">3</span><h2>Create your admin account</h2></div>
    <label>Admin username</label>
    <input id="adminuser" oninput="refresh()" autocomplete="off" placeholder="e.g. soc-admin">
    <div class="row">
      <div><label>Password</label><input id="adminpw" type="password" oninput="refresh()" autocomplete="new-password"></div>
      <div><label>Confirm password</label><input id="adminpw2" type="password" oninput="refresh()" autocomplete="new-password"></div>
    </div>
    <div class="status" id="s-admin"></div>
    <div class="note">This is how you sign in to the console. Add analyst accounts for your team once you're in.</div>
  </div>

  <button class="launch" id="launch" disabled onclick="launch()">Initialize CerberusAI</button>
  <div class="foot" id="foot">Complete the steps above to activate.</div>
</main>
<script>
let siemOk=false, keyOk=false;
const FIRST_RUN = __FIRST_RUN__;
const CONFIGURED = __CONFIGURED__;
const $=id=>document.getElementById(id);
if(!FIRST_RUN && $('admin-card')) $('admin-card').style.display='none';
if(CONFIGURED){
  const cards=document.querySelectorAll('.card');
  if(cards[0]) cards[0].style.display='none';   // SIEM (already connected)
  if(cards[1]) cards[1].style.display='none';   // AI (already connected)
  siemOk=true; keyOk=true;
  const h=document.querySelector('h1'); if(h) h.textContent='Set up your sign-in';
  const s=document.querySelector('.sub'); if(s) s.textContent='This deployment is already connected — just create your admin account to secure the console.';
}
function adminBody(){return{username:$('adminuser').value.trim(),password:$('adminpw').value};}
function adminValid(){
  if(!FIRST_RUN) return true;
  const u=$('adminuser').value.trim(),p=$('adminpw').value,p2=$('adminpw2').value;
  if(!u||!p){setStatus($('s-admin'),'','');return false;}
  if(p.length<8){setStatus($('s-admin'),'err','Password must be at least 8 characters.');return false;}
  if(p!==p2){setStatus($('s-admin'),'err','Passwords do not match.');return false;}
  setStatus($('s-admin'),'ok','Looks good.');return true;}
function onProvider(){const o=$('provider').selectedOptions[0];$('index').value=o.dataset.index;}
onProvider();
function siemBody(){return{provider:$('provider').value,url:$('url').value.trim(),user:$('user').value.trim(),
  password:$('password').value,index:$('index').value.trim(),min_level:parseInt($('minlevel').value||'5'),
  verify_tls:$('verify').checked};}
function setStatus(el,cls,msg){el.className='status '+cls;el.textContent=msg;}
function refresh(){const ready=siemOk&&keyOk&&adminValid();$('launch').disabled=!ready;
  $('foot').textContent=ready?'Ready — click to activate.':'Complete the steps above to activate.';}
async function testSiem(){setStatus($('s-siem'),'wait','Testing connection…');siemOk=false;refresh();
  try{const r=await(await fetch('/api/test-connection',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(siemBody())})).json();
    siemOk=r.ok;setStatus($('s-siem'),r.ok?'ok':'err',(r.ok?'✓ ':'✕ ')+r.message);}catch(e){setStatus($('s-siem'),'err','✕ '+e);}refresh();}
function onAi(){const p=$('aiprovider').value;const o=$('aiprovider').selectedOptions[0];
  $('aimodel').value=o.dataset.model;
  $('ep-wrap').style.display=(p==='azure'||p==='custom')?'block':'none';
  $('ver-wrap').style.display=(p==='azure')?'block':'none';
  $('l-model').textContent=(p==='azure')?'Deployment Name':'Model name';}
onAi();
function aiBody(){return{provider:$('aiprovider').value,model:$('aimodel').value.trim(),
  api_key:$('aikey').value.trim(),endpoint:$('aiendpoint').value.trim(),api_version:$('aiver').value.trim()};}
async function testLLM(){setStatus($('s-key'),'wait','Verifying AI connection…');keyOk=false;refresh();
  try{const r=await(await fetch('/api/test-llm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ai:aiBody()})})).json();
    keyOk=r.ok;setStatus($('s-key'),r.ok?'ok':'err',(r.ok?'✓ ':'✕ ')+r.message);}catch(e){setStatus($('s-key'),'err','✕ '+e);}refresh();}
async function launch(){if(!adminValid())return;$('launch').disabled=true;$('foot').textContent='Initializing engine…';
  const payload={};if(!CONFIGURED){payload.siem=siemBody();payload.ai=aiBody();}if(FIRST_RUN)payload.admin=adminBody();
  try{const r=await(await fetch('/api/save-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})).json();
    if(r.ok){$('foot').textContent='Launching operations console…';setTimeout(()=>window.location='/',1200);}
    else{$('foot').textContent='Save failed.';$('launch').disabled=false;}}
  catch(e){$('foot').textContent='Error: '+e;$('launch').disabled=false;}}
</script>
</body></html>"""


LOGIN_PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CerberusAI — Sign in</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700;800;900&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{--bg:#F5F6F8;--card:#fff;--ink:#0A0C10;--body:#4A4F59;--faint:#9CA1AC;--line:#E5E7EC;--line2:#D6D9E0;--esc:#E11900;--ok:#0E7A46}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);
    font-family:'Archivo',system-ui,sans-serif;letter-spacing:-0.01em;display:grid;place-items:center}
  .mono{font-family:'IBM Plex Mono',monospace;letter-spacing:0}
  .box{width:370px;max-width:92vw}
  .brand{display:flex;align-items:center;gap:11px;justify-content:center;margin-bottom:22px}
  .mark{width:34px;height:34px;background:#0A0C10;border-radius:9px;display:grid;place-items:center}
  .mark svg{width:19px;height:19px}
  .wm{font-weight:900;font-size:21px;letter-spacing:-0.03em}.wm span{color:var(--esc)}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:26px 26px 24px;
    box-shadow:0 1px 2px rgba(15,23,42,.04),0 18px 44px rgba(15,23,42,.07)}
  h1{font-size:16px;font-weight:800;letter-spacing:-0.01em;margin:0 0 3px;text-align:center}
  .sub{text-align:center;color:var(--faint);font-size:12.5px;margin:0 0 22px}
  label{display:block;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);margin:14px 0 6px}
  input{width:100%;padding:11px 13px;border:1px solid var(--line2);border-radius:9px;font-size:14px;
    font-family:'IBM Plex Mono',monospace;background:#fff;color:var(--ink)}
  input:focus{outline:none;border-color:var(--ink);box-shadow:0 0 0 3px rgba(10,12,16,.08)}
  button{width:100%;margin-top:20px;padding:13px;border:none;border-radius:10px;background:var(--ink);color:#fff;
    font-family:'Archivo';font-weight:800;font-size:14px;cursor:pointer;letter-spacing:.01em}
  button:hover{background:#1a1e26}button:disabled{background:#C9CDD5;cursor:not-allowed}
  .err{margin-top:14px;min-height:16px;font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--esc);text-align:center}
  .foot{text-align:center;color:var(--faint);font-size:11px;margin-top:18px}
</style></head>
<body>
  <div class="box">
    <div class="brand">
      <span class="mark"><svg viewBox="0 0 24 24" fill="none"><path d="M12 2.6 4.5 5.6v5.7c0 4.6 3.2 7.6 7.5 9 4.3-1.4 7.5-4.4 7.5-9V5.6L12 2.6Z" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/><path d="M8.7 12.2l2.3 2.3 4.3-4.6" stroke="#E11900" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
      <span class="wm">CERBERUS<span>/</span>AI</span>
    </div>
    <div class="card">
      <h1>Sign in</h1>
      <p class="sub">Operations console access</p>
      <form onsubmit="return signin(event)">
        <label>Username</label>
        <input id="u" autocomplete="username" autofocus>
        <label>Password</label>
        <input id="p" type="password" autocomplete="current-password">
        <button id="btn" type="submit">Sign in</button>
        <div class="err" id="err"></div>
      </form>
    </div>
    <div class="foot mono">CerberusAI · autonomous SOC</div>
  </div>
<script>
async function signin(e){e.preventDefault();const b=document.getElementById('btn');const err=document.getElementById('err');
  b.disabled=true;err.textContent='';
  try{const r=await(await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})})).json();
    if(r.ok){window.location='/';}else{err.textContent=r.message||'Sign in failed.';b.disabled=false;}}
  catch(ex){err.textContent='Error: '+ex;b.disabled=false;}
  return false;}
</script>
</body></html>"""
