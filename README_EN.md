# 🚀 SNI Scanner

> Advanced Python terminal tool for testing SNI, Host headers, CDN/front-domain behavior, proxy-style config details, real connectivity, cache-assisted scans, and stability checks.

🌍 Languages: [English main README](README.md) | [🇮🇷 فارسی](README_FA.md) | [📢 Support](SUPPORT.md)

---

## ⭐ Support the Project

If this project is useful for you, please consider giving it a **Star ⭐** on GitHub. It helps the project grow and motivates further development.

---

## ⚠️ Responsible Use

This tool is intended for testing configurations, domains, and networks that you own or are authorized to test. You are responsible for how you use it. Always follow your local laws, ISP rules, and the terms of service of the platforms and providers you use.

---

## ✨ Main Features

- Paste full config links or enter config specs manually
- Smart config detection and scanner recommendation
- CDN / WS / HTTP scanner with A/B/C modes
- Simple SNI scanner for TLS-based configs
- Real connection test for WS/HTTP/TLS scenarios
- Fake result filtering and A-only filtering
- Live scan progress output
- Selective result saving for Mode B, Mode C, or B+C
- Cache system for faster repeated scans
- Stability test for repeated verification
- Configurable Smart Retry
- TLS security checks for TLS-based configs
- File-based list selection from `data/sni_lists`
- Results saved only in `data/results`
- Built-in Help and Settings screens

---

## 📦 Requirements

### Required

- Python **3.9+**
- pip
- Internet access for first dependency installation
- Terminal, CMD, PowerShell, or Windows Terminal

### Recommended

- Python **3.10, 3.11, or 3.12**
- Stable internet connection
- Correct system date/time, especially for TLS checks
- Your own direct internet connection for more accurate results

---

## 🌐 Network Recommendation

For the most accurate results, run the scanner using **your own normal internet connection**.

VPNs, proxies, strict firewalls, antivirus web shields, or unusual DNS settings may change scan results. If the results look strange:

- test once with a direct connection,
- try a different DNS,
- temporarily disable unrelated VPN/proxy software,
- adjust Timeout or Smart Retry,
- repeat the scan with the same list.

---

## 🛠 Installation & Run

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the app

On Windows:

```bat
run.bat
```

Or directly with Python:

```bash
python main.py
```

> The app is designed to avoid reinstalling dependencies when they are already available.

---

## 🧭 Recommended Workflow

1. Start with **Option 4 ⭐**.
2. Paste a full config or enter specs manually.
3. Let the app detect the config type and suggest the proper scanner.
4. Run the recommended scan.
5. Save valid results from Mode B or Mode C.

---

## 📋 Program Options

### ⭐ Option 4 — Config / Manual Specs

This should usually be the first section you use. It allows you to:

- paste a full config,
- enter specs manually,
- set network type, security, Host, SNI, Path, and Port,
- get a recommended scan type.

Manual entry is supported for users who do not have a full config link.

---

### Option 1 — CDN / WS / HTTP Scanner

Use this for configs involving CDN, Host Header, WS, HTTP, XHTTP, or front-domain behavior.

Good for configs such as:

- `network=ws`
- `network=http`
- `network=xhttp`
- `security=none`
- configs where Address and Host are different

This is usually the most important scanner for CDN-style configs.

---

### Option 2 — Simple SNI Scanner

Use this for simple TLS/SNI checks.

Good for:

- direct TLS configs,
- fast SNI checks,
- basic handshake testing.

This is not always the best choice for complex CDN/WS/HTTP configs. If your config has Host Header or WS/HTTP behavior, Option 1 is usually more accurate.

---

### Option 3 — Batch / Multi Config Scan

Use this when you need to test multiple configs or multiple inputs more quickly.

---

### Settings

Settings can control:

- Smart Retry: 0 to 3
- Timeout
- Worker / Thread count
- DNS Mode
- Cache
- Stability Test

Settings should apply globally across the main scan sections.

---

### Help

The built-in help screen shows a short guide for scan modes and app behavior.

---

## 🧠 A / B / C Mode Meaning

| Mode | Meaning | Reliability |
|---|---|---|
| A | Test using the config IP or target | Low / helper only |
| B | Test using the domain's real DNS IP | Important |
| C | Test using alternate/CDN IPs | Important |

### Important

A result with only **A = OK** is usually not reliable. The app tries not to save A-only results as valid output. Mode B and Mode C are usually the important modes for usable results.

---

## 🧪 Real Connection Test

Real Connection Test goes beyond a simple visible OK result. Depending on the config type, the app attempts a more realistic check:

- `ws + none`: WebSocket/HTTP-style check with Host and Path
- `ws/http/xhttp + tls`: TLS plus Host/Path check
- `tcp + tls`: TLS handshake check
- `tcp + none`: basic TCP connectivity check

---

## 🔁 Smart Retry

Smart Retry can improve accuracy, but it may increase scan time.

| Value | Meaning |
|---|---|
| 0 | Off / fastest |
| 1 | Normal |
| 2 | More accurate |
| 3 | Maximum / slower |

Use `0` or `1` for speed. Use `2` or `3` when accuracy matters more.

---

## 📦 Cache

Cache speeds up repeated scans. If a domain has already been tested, the app can reuse the cached result.

Benefits:

- faster repeated scans,
- fewer duplicate checks,
- useful for large lists.

---

## 🧪 Stability Test

Stability Test helps identify results that are not consistently working. It can repeat checks to confirm whether a result is stable.

This improves quality, but may increase scan time.

---

## 📁 SNI List Files

List files are stored here:

```text
data/sni_lists/
```

Common files:

| File | Purpose |
|---|---|
| `default.txt` | General list |
| `default_sni.txt` | TLS/SNI-focused list |
| `iran.txt` | Suggested Iranian domains |
| `custom.txt` | User custom list |

When you choose `File` inside the app, you can select one of these files.

---

## 💾 Saving Results

Results are saved here:

```text
data/results/
```

You can choose:

- Mode B only
- Mode C only
- Mode B + C

The app should not save broken results or A-only results as valid results.

---

## 🧹 Project Structure

```text
SNI_Scanner/
├─ main.py
├─ run.bat
├─ requirements.txt
├─ README.md
├─ README_EN.md
├─ SUPPORT.md
├─ data/
│  ├─ sni_lists/
│  ├─ results/
│  ├─ cache/
│  └─ logs/
```

---

## 🐞 Issues & Suggestions

If you encounter an issue or have a suggestion, contact the developer on Telegram:

👉 **Telegram:** `@Hunter23_S`

For better issue reports, include:

- Operating system
- Python version
- Menu option used
- Screenshot or exact error text
- Config type: TLS or non-TLS
- Network type: WS, HTTP, XHTTP, GRPC, or TCP

Please remove private data before sending anything. Do not publicly share UUIDs, passwords, private server addresses, or personal configs.

---

## 📜 License

MIT License
