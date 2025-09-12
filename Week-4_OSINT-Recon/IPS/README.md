# 🛡️ Intrusion Prevention System (IPS) – Python & PyQt5

## 📌 Overview
This project is a **lightweight Intrusion Prevention System (IPS)** built in **Python** with a **PyQt5 GUI dashboard**.  
It allows SOC analysts and security researchers to **monitor live network traffic or analyze PCAP files**, detect malicious activity, and (unlike an IDS) **block suspicious hosts automatically**.

The IPS includes:
- Real-time **packet sniffing** and **rule-based detection**
- **Prevention logic** to block malicious IPs automatically
- An **interactive GUI dashboard** for monitoring alerts
- **Charts & visualizations** for live detection insights
- **Persistent logging** for post-analysis (JSON + CSV)

---

## ⚙️ Features

### 🔍 Detection Rules
- **ICMP Floods** → Detects ping flood attacks (exceeding threshold)  
- **TCP SYN Floods / Half-open connections** → Detects repeated SYNs without ACKs  
- **Port Scans** → Flags hosts probing multiple unique ports  
- **Repeated Port Attempts** → Detects brute force / suspicious retries on the same port  
- **Suspicious Payloads** → Detects common malicious patterns like:
  - SQL injection attempts (e.g., `' OR 1=1`, `DROP TABLE`)  
  - XSS payloads (e.g., `<script>`)  
  - Other string/regex matches  

### 🚫 Prevention Rules
- Malicious IPs are **automatically blocked** (user-space/blocklist in GUI)  
- Blocked IPs appear in a **Blocklist table**  
- Analysts can **unblock manually** via the GUI  

### 🖥️ GUI Dashboard (PyQt5)
- **Controls Section** → Start/Stop Live Capture, Load/Analyze PCAPs  
- **Threshold Settings** → Adjustable sliders with units (ICMP/SYN thresholds)  
- **Threat Logs** → Timeline of detected/blocked threats with severity color coding  
- **Blocklist** → Automatically blocked IPs with unblock option  
- **Packet Analysis (Collapsible)** → Detailed per-alert analysis  
- **Monitoring Section** → Charts and graphs for threat activity  

### 📊 Visualizations
- **Line Chart** → Alerts over time  
- **Pie Chart** → Threat distribution by type  
- **Bar Chart** → Flood detection counts  
- Graphs are **triggered only when suspicious activity is detected** (idle on app start)  

### 📝 Logging
- Alerts saved in:
  - `alert_history.json` (structured logs)  
  - `alert_history.csv` (quick review in Excel/LibreOffice)  

---

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/your-username/ips-tool.git
cd ips-tool
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Install system dependencies (Linux)

For live packet capture:

```bash
sudo apt update
sudo apt install libpcap-dev
```

---

## ▶️ Usage

### Run the IPS GUI

```bash
sudo python3 ips_gui.py
```

> ⚠️ `sudo` (or equivalent permissions) is required for live packet sniffing.

---

## 🔄 Workflow

### 1. Start Live Capture

* Click **Start Live** and enter a network interface (e.g., `eth0`, `wlan0`, `lo`)
* The tool analyzes packets in real-time and **blocks** suspicious hosts

### 2. Analyze PCAP Files

* Click **Load PCAP** and choose a `.pcap` or `.pcapng` file
* Click **Analyze PCAP** to replay and detect events from the capture

### 3. Respond to Alerts

* Review **Threat Logs**: time, source IP, threat type, severity, action, reason
* Inspect **Packet Analysis** (expand the collapsible section)
* Use the **Blocklist** table to unblock IPs if needed

### 4. Monitor Graphs

* Charts display **alerts over time**, **threat distribution**, and **flood counts**
* Graphs remain idle until the first suspicious activity is detected

---

## 📂 Project Structure

```bash
IPS/
│── ips_gui.py             # Main IPS GUI application
│── pcap_generator.py      # (optional) demo PCAP generator
│── attacker.py            # Test attacker script (simulates malicious traffic)
│── requirements.txt       # Python dependencies
│── payload_patterns.json  # Payload patterns used for detection
│── alert_history.json     # Saved alerts (auto-generated)
│── alert_history.csv      # Alerts in CSV (auto-generated)
│── README.md              # Documentation
```

---

## 🧪 Testing

### 1. Using Demo PCAPs

* Use `pcap_generator.py` (if included) to generate normal and malicious PCAP files
* Load the generated PCAP via **Load PCAP** and click **Analyze PCAP**

### 2. Simulated Attacks (attacker.py)

Run the provided attacker script to simulate malicious traffic:

```bash
python3 attacker.py
```

This script generates:

* ICMP floods (ping floods)
* SYN floods
* Suspicious HTTP payloads

### 3. Verify in GUI

* Threat logs populate as detections occur
* Blocklist updates automatically with flagged IPs
* Monitoring charts start updating after the first alert

---

## ⚖️ Limitations

* This is a **lightweight demo IPS** — not a production-grade enterprise solution
* Blocking is done in **user space** (not kernel-level `iptables`)
* Best suited for **learning, labs, and proof-of-concepts**

---

## 🚀 Roadmap / Future Improvements

* Add **regex-based payload detection**
* Support **GeoIP lookups** for flagged IPs
* Add **alert filtering** by severity
* Enhance **packet analysis** with header + hex payload views
* Integration with **SIEM tools**

---

## 📜 License

This project is licensed under the **MIT License** — free to use, modify, and share.
