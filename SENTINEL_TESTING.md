# Validating CerberusAI against a real Microsoft Sentinel

The Sentinel adapter is engineered and unit-tested, but until it has run against a
live workspace, treat it as **unverified** — the goal of this guide is to close that
gap using a **free** Azure account and Microsoft's own sample data. Budget ~45 minutes
(most of it waiting for sample data to load).

At the end you'll have run `probe_siem.py` against real Sentinel and confirmed the
field mapping is correct — not just that it connects.

---

## What you're building

```
Azure free account
  └─ Log Analytics workspace          (where the logs live)
       └─ Microsoft Sentinel enabled  (the SIEM layer on top)
            └─ Training Lab sample data (real SecurityEvent / SigninLogs rows)
  └─ Entra ID app registration        (the read-only identity CerberusAI logs in as)
       └─ Log Analytics Reader role on the workspace
```

CerberusAI needs **four values** from this: Tenant ID, Workspace ID, Application
(client) ID, and a client secret.

---

## Step 1 — Azure free account

Sign up at **azure.microsoft.com/free**. It's free ($200 credit for 30 days plus
always-free services), but Microsoft requires a **credit card for identity
verification** — you won't be charged on the free tier, and we delete everything at
the end. If you already have an Azure/work tenant you can use, skip this.

## Step 2 — Create a Log Analytics workspace

Azure Portal → search **Log Analytics workspaces** → **Create** → pick (or create) a
Resource Group, give the workspace a name, choose a region → **Review + Create**.

> Tip: put everything in one Resource Group (e.g. `cerberus-test`) — deleting that one
> group at the end removes all of it and stops any billing.

## Step 3 — Enable Microsoft Sentinel

Portal → search **Microsoft Sentinel** → **Create** → **+ Add** → select the workspace
from Step 2 → **Add**. Sentinel's first **31 days on a workspace are free**.

## Step 4 — Load sample data (the part that makes this a real test)

Inside Microsoft Sentinel → **Content hub** → search **Training Lab** → open
**Microsoft Sentinel Training Lab** → **Install**. Then open the installed solution and
run its deployment to ingest the sample data.

This backfills real **SecurityEvent** (Windows 4624/4625 logons), **SigninLogs**, and
other tables with about a week of data. **It can take 20–30 minutes to appear**, and
the rows are **backdated** (important — see Step 8).

## Step 5 — Confirm the data landed

Sentinel → **Logs** → run:

```kql
SecurityEvent | where EventID in (4624, 4625) | take 20
| project TimeGenerated, EventID, IpAddress, Computer, Account
```

You want rows where **IpAddress** and **Computer** are populated. Those are exactly the
fields our `SecurityEvent` preset maps to — if they're there, the adapter will work. If
this returns nothing yet, the sample data is still loading; wait and retry.

## Step 6 — Create the app registration CerberusAI logs in as

1. Portal → **Microsoft Entra ID** (formerly Azure Active Directory) → **App
   registrations** → **New registration** → name it `CerberusAI-Reader` → **Register**.
2. On its **Overview**, copy the **Application (client) ID** and the **Directory
   (tenant) ID**.
3. **Certificates & secrets** → **New client secret** → copy the **Value** immediately
   (it's only shown once — copy the *Value*, not the Secret ID).

## Step 7 — Give the app read access to the workspace

Go to the **Log Analytics workspace** → **Access control (IAM)** → **+ Add** → **Add
role assignment** → role **Log Analytics Reader** → **Members** → select your
`CerberusAI-Reader` app → **Review + assign**.

> Without this, auth will succeed but every query returns 403.

## Step 8 — Collect your four values

| Wizard field | Where to find it |
|---|---|
| **Directory (tenant) ID** | App registration → Overview |
| **Application (client) ID** | App registration → Overview |
| **Client secret** | The *Value* you copied in Step 6.3 |
| **Log Analytics Workspace ID** | The workspace → **Overview** → "Workspace ID" |

## Step 9 — Plug into CerberusAI and test the connection

Open CerberusAI → **Setup** → **SIEM Platform: Microsoft Sentinel**:

- **Azure cloud:** Commercial (choose Government only if this is a Gov/DoD tenant)
- **Log table:** SecurityEvent (matches the Training Lab data)
- Paste the four values → **Test Connection** → it should go green.

## Step 10 — Validate the field mapping with the probe

This is the real test. Because the sample data is **backdated**, the live poller's
10-minute window won't see it — so probe with a wide window instead:

```bash
python probe_siem.py --window 10080
```

(`10080` minutes = 7 days.) You want to see:

- `[OK] test_connection`
- a list of source IPs with alert counts,
- a `query_source_activity` JSON block with non-zero `failed_auth_count` /
  `successful_auth_count`, populated `sample_logs`, and `targets_contacted`,
- all four `field-mapping sanity` checks `[OK]`.

If `sample_logs` is empty or counts are all zero, the table/field names don't match
your data — adjust `table` or `siem.fields` in `config.json` and re-run. **Tell me what
the probe printed and I'll fix the mapping.**

---

## About the live poller vs. sample data

In **production against live Sentinel**, the poller's short window is correct — real
alerts arrive continuously. The wide-window probe is only needed here because Training
Lab data is historical. So: use the probe to confirm the mapping, and know the live
flow will behave normally once it's pointed at a workspace receiving current data.

## When you're done — stop the meter

Delete the whole **Resource Group** (Portal → Resource groups → your group → Delete).
That removes the workspace, Sentinel, and sample data in one go. The app registration
lives under Entra ID — delete it separately if you like.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Azure AD auth failed` | Wrong tenant ID, client ID, or the secret **Value** (not Secret ID); secret expired |
| Auth OK but `querying 'SecurityEvent' failed` / 403 | App missing **Log Analytics Reader** on the workspace (Step 7) |
| Connects, but probe finds **no sources** | Window too narrow for backdated data — use `--window 10080`; or sample data still loading |
| Probe finds sources but `sample_logs` empty | Field/table mismatch — send me the probe output |
| Government tenant | Set **Azure cloud: Government** in the wizard (uses `login.microsoftonline.us` / `api.loganalytics.us`) |
