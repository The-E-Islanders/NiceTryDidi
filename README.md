# NiceTryDidi 🛡️

**NiceTryDidi** is a local-first Indian SMS and UPI scam detector. It checks messages for high-risk patterns such as UPI PIN/cashback fraud and APK links, then uses a local Ollama model to explain the risk in a selected Indian language.

No SMS content is sent to a cloud AI service: the backend calls Ollama at `http://localhost:11434` on the same computer.

## Features

- Fast deterministic checks for obfuscated PIN/cashback scams and `.apk` links
- Local `qwen2.5:3b` analysis through Ollama
- Hindi, Telugu, Tamil, Bengali, Marathi, Kannada, and Gujarati output
- Streamlit demo interface with judge-ready scam examples
- Cybercrime reporting links and the `1930` helpline shortcut
- Defensive JSON parsing and graceful Ollama error messages

## Project files

```text
NiceTryDidi/
├── app.py       # FastAPI backend
├── ui.py        # Streamlit web interface
└── README.md    # Setup and usage guide
```

## Prerequisites

| Requirement | Recommended version | Why it is needed |
| --- | --- | --- |
| Windows | Windows 10 22H2 or newer | Local development and NVIDIA GPU support |
| Python | 3.10+ (3.13 works) | Runs FastAPI and Streamlit |
| Ollama | Current Windows release | Runs the local language model |
| NVIDIA driver | 551.61+ for NVIDIA GPUs | Enables local GPU acceleration in Ollama |
| Disk space | At least 8 GB free | Ollama app plus the downloaded model |

Ollama’s Windows installer runs as a native app and provides the local API on port `11434`. See the official [Ollama Windows documentation](https://docs.ollama.com/windows) for current platform requirements.

## 1. Install Python

Download and install Python from [python.org/downloads](https://www.python.org/downloads/). During installation, select **Add Python to PATH**.

Verify it in a new PowerShell window:

```powershell
python --version
```

If `python` is not found, use your full Python executable path instead, for example:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe" --version
```

## 2. Install Ollama and the local model

1. Download and run the [Ollama for Windows installer](https://ollama.com/download/windows).
2. Open a **new** PowerShell window after installation.
3. Download the model required by this project:

```powershell
ollama pull qwen2.5:3b
```

Ollama normally starts in the background after installation. If its API is not already available, start it manually in a dedicated terminal:

```powershell
ollama serve
```

Verify that Ollama and the model are available:

```powershell
ollama list
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

The backend uses `qwen2.5:3b` with `num_gpu: 99` and `temperature: 0.1`. Ollama will use the compatible NVIDIA GPU available on the machine; use `ollama ps` during a request to inspect the loaded model.

## 3. Create a Python environment and install dependencies

Open PowerShell in the cloned project directory:

```powershell
cd path\to\NiceTryDidi
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, allow it for this terminal only, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 4. Start NiceTryDidi

Keep Ollama running, then open **two PowerShell terminals** in the project directory and activate `.venv` in each one.

### Terminal 1 — FastAPI backend

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

Verify the backend:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok","model":"qwen2.5:3b"}
```

### Terminal 2 — Streamlit interface

```powershell
.\.venv\Scripts\Activate.ps1
python -m streamlit run ui.py --server.address 0.0.0.0 --server.port 8501
```

Open the app in a browser:

```text
http://127.0.0.1:8501
```

The API documentation is available at `http://127.0.0.1:8000/docs`.

## Test the API directly

```powershell
$body = @{
  message = "Congratulations! Claim ₹2,000 cashback. Enter your UPI PIN now."
  language = "Telugu"
} | ConvertTo-Json

Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/check-scam" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```

## Use from another device on the same Wi-Fi

Find the computer's Wi-Fi IPv4 address:

```powershell
ipconfig
```

Under **Wireless LAN adapter Wi-Fi**, find the `IPv4 Address`, then open:

```text
http://YOUR_IPV4_ADDRESS:8501
```

For example, if `ipconfig` shows `10.30.66.167`, use `http://10.30.66.167:8501`.

Only do this on a trusted private network. If Windows Firewall asks, allow Python on **Private networks**. If it does not prompt and the site cannot be reached, open an elevated PowerShell window and add a rule for the UI port:

```powershell
New-NetFirewallRule -DisplayName "NiceTryDidi UI" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8501
```

## Troubleshooting

| Problem | Check / fix |
| --- | --- |
| `Local Ollama is unreachable` | Run `ollama serve`, then verify `http://127.0.0.1:11434/api/tags`. |
| Model not found | Run `ollama pull qwen2.5:3b`. |
| `ModuleNotFoundError` | Activate `.venv` and rerun the dependency installation command. |
| Port `8000` or `8501` is already in use | Find the process with `Get-NetTCPConnection -LocalPort 8000` (or `8501`) and stop only the confirmed process. |
| Page does not update after a code change | Stop both Python processes and start the backend and Streamlit commands again. |
| Another phone cannot open the UI | Confirm both devices use the same Wi-Fi and permit port `8501` through the Private-network firewall. |
| Selected language shows an unexpected script | Restart the backend after pulling the latest code. The backend now replaces invalid/missing regional-model output with a safe selected-language fallback. |

## Safety note

NiceTryDidi provides a local automated risk assessment, not a legal or financial decision. Never enter or share a UPI PIN, OTP, bank password, or card CVV in response to an SMS. For a confirmed or suspected fraud attempt in India, call **1930** and report it at [cybercrime.gov.in](https://cybercrime.gov.in).
