# SentinelAI 🛡️

### See the traffic. Understand the decision. Verify the protection.

SentinelAI is a Windows-focused network monitoring and demonstration project. It turns captured network packets into **network flows**, asks a machine-learning model whether each flow looks normal or suspicious, and presents the result in a live dashboard. When configured to do so, it can apply a Windows Firewall rule and later remove that rule after a quiet observation period.

> **This is a student and lab project, not a production intrusion-prevention system.** Test only on a computer and network you own or are authorized to monitor. Model output is an estimate and can be wrong.

## What it can do

- **Live monitoring:** capture packets, group them into flows, and show traffic volume and direction.
- **Threat estimates:** classify each analyzed flow as `NORMAL` or `ATTACK` and show the model’s estimated attack probability.
- **Understandable explanations:** show which observed traffic clues influenced the model’s result, in plain language.
- **Adaptive firewall decisions:** choose to allow, monitor, or block based on the prediction, configured risk threshold, and recent activity.
- **Verified enforcement status:** distinguish a decision to block from a rule that Windows Firewall actually created.
- **Quiet-period recovery:** keep an applied block while the source is observed. New suspicious activity restarts the timer; recovery requires the capture monitor to be healthy. The dashboard lets you set the quiet period.
- **Dashboard and history:** overview, alerts, analytics, live connections, model quality, protection settings, and recent recovery activity.
- **Controlled demo:** score a labeled dataset flow and optionally create a temporary rule for a reserved test address, so the detection and recovery path can be demonstrated without sending attack traffic.

## How the decision flow works

```text
Network packets → flow features → NORMAL / ATTACK estimate → allow / monitor / block
                                                        ↓
                         Windows Firewall result → quiet-period observation → recovery
```

The classifier currently uses 14 **flow-level** fields, including protocol, flow duration, packet counts and sizes, transfer rates, and TCP flags. It does not inspect file names, file contents, or encrypted application payloads. A “file upload/download” shown by the dashboard is a traffic-direction and byte-volume estimate, not identification of a specific file.

## Project layout

| Folder / file | Purpose |
| --- | --- |
| `dashboard/` | Browser dashboard (HTML, CSS, JavaScript) |
| `ai/api/` | FastAPI endpoints and dashboard data |
| `capture/` | Packet capture and packet parsing |
| `ai/features/` | Network-flow aggregation |
| `ai/predict/` | Model prediction and explanation text |
| `ai/firewall/` | Adaptive policy, Windows Firewall enforcement, and recovery |
| `ai/logs/` | Runtime prediction, session, and flow state (generated locally) |
| `ai/preprocessing/`, `ai/train/` | Dataset preparation, training, and evaluation |
| `ai/tests/` | Policy, API, lifecycle, and controlled-sample checks |

## Requirements

- Windows 10 or 11 for real Windows Firewall enforcement.
- Python 3.10+ (developed with Python 3.12).
- Npcap installed for packet capture with Scapy; capture may need an elevated PowerShell window.
- A trained model and the dataset files described below. They are intentionally not stored in this repository.

## Setup

Open PowerShell in the cloned project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use `\.venv\Scripts\python.exe` in place of `python` for the commands below.

### Prepare the model

SentinelAI uses the **CIC-IDS2017 Tuesday brute-force traffic data**. Get the dataset from the [Canadian Institute for Cybersecurity CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html) and follow its dataset terms and citation guidance. This project’s preprocessing script expects a compatible Parquet file at:

```text
ai/dataset/raw/Bruteforce-Tuesday-no-metadata.parquet
```

The dataset must include the feature columns selected in `ai/preprocessing/prepare_dataset.py` and a `Label` column. The current supplied data covers benign traffic and FTP/SSH Patator brute-force examples; the model’s output is binary (`NORMAL` / `ATTACK`), not an attack-family diagnosis.

Create the local folders and run preparation/training from the repository root:

```powershell
New-Item -ItemType Directory -Force ai\dataset\raw, ai\dataset\processed, ai\models, ai\logs | Out-Null
python ai\preprocessing\prepare_dataset.py
python ai\train\train_model.py
```

The trained model is written to `ai/models/sentinelai_model.joblib`. The dataset and model are ignored by Git because they can be large and may have separate redistribution terms. The API will not start prediction routes until a compatible trained model exists at that path.

## Run the dashboard

Start the API in a regular PowerShell window. Set the same policy values in both windows so the dashboard and capture process use the same settings. Change the allowlist to match trusted addresses on your own network:

```powershell
$env:SENTINELAI_BLOCK_THRESHOLD = "0.70"
$env:SENTINELAI_FIREWALL_ALLOWLIST = "192.168.1.1,192.168.1.0/24"
python -m uvicorn ai.api.app:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

To capture live traffic, open a **second PowerShell window as Administrator**, go to the same repository folder, set the same policy values, and run:

```powershell
$env:SENTINELAI_BLOCK_THRESHOLD = "0.70"
$env:SENTINELAI_FIREWALL_ALLOWLIST = "192.168.1.1,192.168.1.0/24"
python capture\packet_capture.py
```

Keep both windows open. The dashboard reports API and capture health separately. The default block threshold is `0.70`; `SENTINELAI_BLOCK_THRESHOLD` accepts a value from `0` to `1`. `SENTINELAI_FIREWALL_ALLOWLIST` accepts comma-separated IPv4 addresses and CIDR ranges. Invalid, loopback, non-unicast, and allowlisted sources are protected from automatic blocking by the policy.

## Self-healing quiet period

Use the **Self-healing** section in the dashboard to set how long a successfully blocked source must remain free of suspicious activity before SentinelAI attempts recovery. The allowed range is **10–3600 seconds**. The setting applies to new blocks. Another suspicious prediction restarts the quiet-period timer. If packet capture is unhealthy, SentinelAI keeps the block instead of recovering based on missing observations. The dashboard reports whether the rule was created or removed; a chosen action alone is not proof that enforcement succeeded.

## Try a controlled attack demonstration

The sample check uses a flow from the prepared labeled dataset. It does **not** create malicious traffic. First run a dry demonstration:

```powershell
python ai\tests\test_attack_sample.py
```

For an actual Windows Firewall rule and recovery demonstration, open **Administrator PowerShell** and run:

```powershell
python ai\tests\test_attack_sample.py --enforce
```

This uses the reserved documentation address `192.0.2.123`, applies a rule if Windows accepts it, records enforcement status, and schedules recovery using the configured quiet period. The script removes the rule after the quiet period if monitoring remains healthy; suspicious activity or a failed recovery keeps/reports the rule accordingly. Do not use this demonstration as a test against a real host.

The firewall integration is currently Windows-only and creates inbound IPv4 source-address rules. Run enforcement and lifecycle demonstrations only when you can use Administrator PowerShell.

## Checks

Run from the repository root. Policy and dashboard checks do not create real firewall rules:

```powershell
python -m unittest ai.tests.test_adaptive_firewall ai.tests.test_firewall_policy ai.tests.test_dashboard_stats ai.tests.test_dashboard_integration
```

The following lifecycle and `--enforce` sample checks create/remove a temporary Windows Firewall rule and therefore require Administrator PowerShell:

```powershell
python ai\tests\test_firewall_lifecycle.py
python ai\tests\test_attack_sample.py --enforce
```

Evaluate the current trained model with:

```powershell
python ai\train\evaluate_model.py
```

## Privacy and repository hygiene

Captured traffic metadata, prediction history, local IP addresses, model binaries, and training data can be sensitive or large. They are runtime/local files and should not be committed. `.gitignore` excludes generated logs, datasets, model artifacts, Python environments, and local editor files. Before publishing, review `git status` and confirm no credentials, private traffic records, or dataset files are staged.

## Known limits

- This project makes flow-based estimates; it is not a guarantee that traffic is safe or malicious.
- Training data currently represents benign traffic and selected brute-force attack samples. Results may not generalize to other networks or attack types.
- Explanations describe model clues; they are not proof of malicious intent.
- File names and file contents are not identified by the flow monitor.
- Automatic firewall changes can disrupt connectivity. Configure the allowlist carefully and test in an authorized lab.

## Acknowledgment

The training workflow is designed around the CIC-IDS2017 dataset from the Canadian Institute for Cybersecurity at the University of New Brunswick. Please follow the [dataset page’s terms and citation guidance](https://www.unb.ca/cic/datasets/ids-2017.html) when using it.
