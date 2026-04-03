<div align="center">

# 📡 EchoFlare

### _Find working DNS resolvers in networks that don't want to be found._

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/alisouran/EchoFlare?style=flat-square)](https://github.com/alisouran/EchoFlare/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android-lightgrey?style=flat-square)]()

</div>

---

## 📖 What is EchoFlare?

Standard DNS scanners fail in heavily censored or degraded networks. When you fire 100,000 DNS probes and wait for replies, you hit two hard walls simultaneously:

1. **Socket exhaustion** — keeping tens of thousands of open UDP sockets overwhelms the OS.
2. **DPI detection** — stateful packet inspection identifies the flood pattern and rate-limits or drops your traffic.

**EchoFlare** solves both problems with a _stateless, fire-and-forget_ architecture inspired by sonar. You send the pings from your restricted network. You never wait for replies. An external server outside the restricted network catches whatever makes it through — and that's your result set.

---

## 🧠 How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          EchoFlare Architecture                         │
└─────────────────────────────────────────────────────────────────────────┘

  YOUR DEVICE (Restricted Network)              EXTERNAL VPS
  ┌────────────────────────────┐                ┌──────────────────────────┐
  │                            │                │                          │
  │   📦 Scattergun            │   UDP/53 ───►  │   🎯 EchoCatcher         │
  │                            │                │                          │
  │   • Reads resolvers.txt    │   ╔══════════╗ │   • Authoritative DNS    │
  │   • Crafts DNS A-queries   │   ║  DPI /   ║ │     server for           │
  │   • Encodes target IP +    ├──►║  Firewall║─┤     scan.yourdomain.com  │
  │     timestamp in QNAME     │   ║  >80%    ║ │   • Decodes target IP    │
  │   • Fire-and-forget UDP    │   ║  loss    ║ │     from QNAME           │
  │   • No response reading    │   ╚══════════╝ │   • Logs resolver hits   │
  │                            │                │     as structured JSON   │
  │   🤖 Orchestrator Bot      │                │   • Replies with dummy   │
  │                            │                │     A record (1.2.3.4)   │
  │   • Telegram control plane │◄───────────────│     to silence retries   │
  │   • Safely swaps Port 53   │   Results via  │                          │
  │     between VPN ↔ Scanner  │   Telegram     │   working_resolvers.json │
  │   • Health monitoring      │                │                          │
  └────────────────────────────┘                └──────────────────────────┘
```

| Component | Runs On | Role |
|---|---|---|
| **Scattergun** | Your device / Termux | Reads `resolvers.txt`, blindly fires DNS queries encoded with each resolver's IP and a timestamp. Never reads responses. |
| **EchoCatcher** | External VPS | Authoritative nameserver that decodes incoming queries, extracts the resolver IP and latency, and logs structured JSON results. |
| **Orchestrator Bot** | VPS (same or separate) | Telegram bot that manages the scan lifecycle and your VPN — safely handing off Port 53 so you never lose connectivity. |

---

## ⚠️ Crucial Concept — Read This First

> **Scattergun MUST be run from inside the restricted network you are testing.**

This is the entire point of the tool. If you run Scattergun on the VPS, you are scanning *from outside* the restriction — your results will be meaningless and won't reflect what actually works for your users.

| Where to run | Correct? |
|---|---|
| Your home Wi-Fi or mobile data (the restricted network) | ✅ Yes |
| Termux on your Android phone (on the restricted network) | ✅ Yes |
| Your VPS / cloud server | ❌ No — wrong side of the firewall |
| Any server with unrestricted internet access | ❌ No |

---

## 🚀 Quick Start

There are two distinct phases. The **server** (VPS) is set up once. The **client** (Scattergun) is run from your restricted local network every time you want to scan.

---

### Phase 1: The Brain — VPS / Server Setup

> Run this **on your VPS** as root. This is a one-time setup.

```bash
bash <(curl -sSL https://raw.githubusercontent.com/alisouran/EchoFlare/main/install.sh)
```

The installer will walk you through everything interactively. It will:

1. Install system dependencies (`git`, `curl`, `wget`)
2. Download and install the latest stable Go (if not present or below 1.22)
3. Clone the repository
4. Prompt you for your **Telegram Bot Token**, **Telegram User ID**, and **scan domain**
5. Write `/opt/dns-orchestrator/config.yaml` with secure permissions (`600`)
6. Compile `orchestrator-bot` and `echocatcher` to `/usr/local/bin/`
7. Create and enable `orchestrator-bot.service` (auto-restart on crash)
8. Inject a passwordless `sudoers` rule for `systemctl` service control
9. Start the bot and send you a "🤖 Bot started" message on Telegram

**Requirements:**
- Ubuntu 20.04+ / Debian 11+ VPS with a public IP
- A domain where you control DNS (to add an NS record pointing `scan.yourdomain.com` to your VPS)
- A Telegram bot token from [@BotFather](https://t.me/BotFather)
- Your numeric Telegram user ID from [@userinfobot](https://t.me/userinfobot)

**DNS Delegation (required):**

Add these two records in your domain's DNS settings:
```
scan.yourdomain.com.  IN  NS  vps.yourdomain.com.
vps.yourdomain.com.   IN  A   YOUR.VPS.IP.ADDRESS
```

This makes your VPS the authoritative server for `scan.yourdomain.com`, so all probe queries route to EchoCatcher.

---

### Phase 2: The Muscle — Client Setup (Scattergun)

> Run this **on your local device, connected to the restricted network** you want to test.

**You do NOT need to install Go.** Just download the pre-compiled binary.

#### Step 1 — Download the binary

Go to the [**GitHub Releases page**](https://github.com/alisouran/EchoFlare/releases/latest) and download the archive for your device:

| Your Device | File to download |
|---|---|
| Linux PC / Server (x86-64) | `scattergun-linux-amd64.tar.gz` |
| Linux (ARM, e.g. Raspberry Pi) | `scattergun-linux-arm64.tar.gz` |
| macOS (Apple Silicon M1/M2/M3) | `scattergun-darwin-arm64.tar.gz` |
| macOS (Intel) | `scattergun-darwin-amd64.tar.gz` |
| Windows PC | `scattergun-windows-amd64.zip` |
| Android (Termux) | `scattergun-android-arm64.tar.gz` |

#### Step 2 — Extract the archive

**Linux / macOS / Android (Termux):**
```bash
tar -xzf scattergun-*.tar.gz
chmod +x scattergun
```

**Windows:**
Right-click the `.zip` file → "Extract All".

#### Step 3 — Add your resolver list

Place a file called `resolvers.txt` in the **exact same folder** as the `scattergun` binary. This file is a plain list of DNS resolver IP addresses to test, one per line:

```
8.8.8.8
8.8.4.4
1.1.1.1
9.9.9.9
208.67.222.222
...
```

> Your folder should look like this:
> ```
> my-scan-folder/
> ├── scattergun          ← (or scattergun.exe on Windows)
> └── resolvers.txt       ← one resolver IP per line
> ```

You can find public resolver lists online, or use your own curated list.

#### Step 4 — Run the scan

Open a terminal in that folder and run:

**Linux / macOS / Android (Termux):**
```bash
./scattergun -list resolvers.txt -domain scan.yourdomain.com
```

**Windows:**
```cmd
scattergun.exe -list resolvers.txt -domain scan.yourdomain.com
```

---

## 🎯 How to Perform Your First Scan

Follow these steps in order. The whole process takes about 5–10 minutes.

**Step 1 — Tell the server to start listening**

Open Telegram and send this command to your bot:
```
/scan 5m
```
The bot will stop the VPN, start EchoCatcher (the receiver), and confirm it's ready:
```
Bot: ✅ EchoCatcher started. Scanning for 5m...
```

**Step 2 — Fire the packets from your restricted network**

On your local device (home Wi-Fi, mobile data, etc.), open a terminal in the folder containing `scattergun` and `resolvers.txt`, then run:

```bash
# Linux / macOS / Android
./scattergun -list resolvers.txt -domain scan.yourdomain.com
```
```cmd
# Windows
scattergun.exe -list resolvers.txt -domain scan.yourdomain.com
```

You'll see a live progress counter. Let it run through your full resolver list.

**Step 3 — Collect your results**

Wait for the timer to complete (5 minutes in this example). The bot will automatically:
- Stop EchoCatcher
- Package the results
- Send you the `working_resolvers.json` file directly in Telegram
- Restart your VPN

```
Bot: 📎 working_resolvers.json — 1,247 resolver hits
Bot: ✅ Scan complete! VPN has been restarted.
```

Open `working_resolvers.json` — every entry is a resolver that successfully relayed a probe through the firewall, complete with latency data.

---

## 📱 Telegram Bot Commands

The Orchestrator Bot is your remote control. It handles the Port 53 hand-off automatically so you never lose VPN connectivity.

### Admin commands

| Command | What it does |
|---|---|
| `/scan <duration>` | Full scan lifecycle: stop VPN → start EchoCatcher → wait → send results file → restart VPN. Example: `/scan 5m` or `/scan 10m` |
| `/status` | Live service states + server CPU% and RAM, plus registered user count |
| `/toggle_vpn` | Start the VPN if stopped; stop it if running |
| `/get_logs` | Last 50 lines of VPN service logs |
| `/broadcast <message>` | Send a message to all registered users |

### Public commands (non-admin users)

| Command | What they see |
|---|---|
| `/start`, `/help` | A friendly welcome message |
| `/status` | Simple "online / scanning / maintenance" status |
| Any admin command | ⛔ Access Denied |

---

## 🔐 Security & Access Control

### How access works

The `owner_id` in `config.yaml` is the sole **Admin**. Everyone else gets a read-only public view. Non-admin users are never silently ignored — they receive a clear `⛔ Access Denied` reply for restricted commands. This is intentional: the bot is often shared with the people who benefit from the network being optimized.

### User registry

Every user who sends `/start` or `/status` is automatically registered in `/opt/dns-orchestrator/users.json`:

```json
{
  "ids": [111222333, 444555666, 777888999]
}
```

The file is written atomically (write-to-temp + rename) so a crash never corrupts it.

### Broadcast

Once users are registered, the admin can reach all of them with one command:

```
/broadcast Server maintenance in 5 minutes. VPN may be briefly interrupted.
```

The bot reports a delivery summary:
```
📣 Broadcast complete
✅ Sent: 42  |  ⛔ Blocked/left: 3  |  ⚠️ Failed: 0
```

Users who have blocked the bot are gracefully skipped — they do not cause the broadcast to fail.

---

## ✨ Features

- **Stateless scanning** — fire-and-forget UDP means zero socket accumulation and no DPI fingerprint
- **Packet-loss resilient** — configurable retry count (`-retries 3`) with random jitter to beat probabilistic dropping
- **Telegram control plane** — start scans, check server health, toggle VPN, and receive result files without ever SSH-ing into your VPS
- **Port-53 conflict resolution** — the Orchestrator Bot safely stops the VPN before scanning and restarts it afterwards, preventing lockouts
- **Proactive health alerts** — background monitor pings `8.8.8.8` every 5 minutes; if packet loss exceeds your threshold, the bot DMs you an alert
- **Structured JSON logging** — every resolver hit is a complete NDJSON record with `target_ip`, `forwarder_ip`, `latency_sec`, and `timestamp`
- **Cross-platform** — Linux (amd64/arm64), macOS (Apple Silicon + Intel), Windows (amd64), and **Android via Termux** (arm64)
- **Pre-built binaries** — no Go installation needed on the client side

---

## ⚙️ Scattergun Flags (Advanced)

```bash
./scattergun -list resolvers.txt -domain scan.yourdomain.com [options]
```

| Flag | Default | Description |
|---|---|---|
| `-list` | (required) | Path to newline-separated resolver IP file |
| `-domain` | (required) | Your EchoCatcher zone (e.g. `scan.yourdomain.com`) |
| `-workers` | `200` | Concurrent sender goroutines |
| `-retries` | `3` | UDP sends per IP (mitigates packet loss) |
| `-jitter` | `10ms` | Max random delay between retries |

---

## 🔒 Security Notes

- `config.yaml` is written with `chmod 600` by the installer — your Telegram token is never world-readable.
- The bot silently ignores all messages from non-owners; it does not reveal its existence to strangers.
- The `sudoers` rule is validated with `visudo -c -f` before installation to prevent lockouts.
- `install.sh` should be reviewed before piping to bash — as with any installer.
- EchoCatcher should be deployed behind a firewall that only allows UDP/53 inbound.

---

## 📦 Project Structure

```
EchoFlare/
├── scattergun/
│   └── main.go              ← fire-and-forget UDP sender
├── echocatcher/
│   └── main.go              ← authoritative DNS receiver + NDJSON logger
├── bot/
│   └── main.go              ← Telegram orchestrator bot
├── config.yaml              ← sample configuration (do not commit with real tokens)
├── orchestrator.service     ← systemd unit file template
├── install.sh               ← automated one-command VPS installer
├── Makefile                 ← cross-compilation targets
├── build.sh                 ← shell-based cross-compile script
├── go.mod
└── go.sum
```

---

## 🛠️ Building from Source (Optional)

If you prefer to compile yourself:

```bash
git clone https://github.com/alisouran/EchoFlare.git
cd EchoFlare
go mod tidy

# Build everything for all platforms
make build-all

# Or individual targets:
make build-linux-amd64     # scattergun + echocatcher for Linux x86-64
make build-linux-arm64     # Linux ARM64
make build-darwin-arm64    # macOS Apple Silicon
make build-bot             # orchestrator bot (Linux amd64, for VPS)
make build-android-arm64   # scattergun only — for Termux on Android
```

Binaries are written to `bin/` with platform suffixes.

---

## 🤝 Contributing

Contributions are welcome. EchoFlare is most useful when it works across the widest possible range of restricted network environments — experience with DPI evasion, DNS tunnelling, or mobile networking is especially valuable.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit with a clear message: `git commit -m "feat: add IPv6 resolver support"`
4. Push and open a Pull Request against `main`

Please ensure `go vet ./...` passes and include a brief description of what changed and why.

---

## 📜 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

---

## ⚠️ Disclaimer

EchoFlare is developed for **educational purposes and legitimate network diagnostics** — specifically for users who need to identify functional DNS resolvers in degraded or heavily filtered network environments (e.g., to maintain connectivity in censored regions).

**You are solely responsible for ensuring your use complies with applicable laws and the terms of service of any networks you operate on.** The authors do not condone or support any use of this tool for unauthorized access, surveillance, or disruption of services.

---

<div align="center">

Made with ☕ and packet loss.

[Report a Bug](https://github.com/alisouran/EchoFlare/issues) · [Request a Feature](https://github.com/alisouran/EchoFlare/issues) · [Discussions](https://github.com/alisouran/EchoFlare/discussions)

</div>
