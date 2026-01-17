# Windows WiFi MitM Detector (ARP/DNS/Deauth)

A **Windows-compatible** WiFi MitM detector that scans for:
- **ARP spoofing** (gateway/client MAC changes)
- **DNS spoofing** (suspicious multi-IP replies)
- **Deauth flood** (802.11 deauth frames, if available)

> ⚠️ Use **only on networks you own or have explicit permission to test**.

---

## Repo
**GitHub:** `Prabesh-Proper`  
Project file: `wifi_mitm_detector_win.py`

---

## Requirements
- **Windows 10/11**
- **Npcap** (WinPcap-compatible mode)
- **Python 3.9+ recommended**

### Install Npcap
1. Download Npcap installer
   - https://npcap.com/dist/npcap-1.79.exe
2. During install, check:
   - ✅ **WinPcap API-compatible mode**

### Install Python dependencies
```bash
pip install scapy numpy
```

---

## Run (Administrator)
Open **Command Prompt / PowerShell as Administrator**:

```bash
python wifi_mitm_detector_win.py
```

Optional (choose interface manually):

```bash
python wifi_mitm_detector_win.py "Wi-Fi"
```

---

## List Interfaces (optional)
```python
from scapy.all import get_if_list
print(get_if_list())
```

---

## What it Detects
### ✅ ARP Spoofing
Alerts when an IP address suddenly maps to a different MAC.

### ✅ DNS Spoofing
Tracks DNS answers and alerts when the same query is seen resolving to different IPs in a suspicious way.

### ⚠️ Deauth Flood (Best-effort)
Detects bursts of `Dot11Deauth` frames if your adapter/driver/Npcap setup exposes 802.11 management frames.

---

## Notes
- Run near the target AP for best results.
- Must be run with **Administrator** privileges.

---

## Disclaimer
This tool is for **authorized security testing and educational use** only. The author is not responsible for misuse.
