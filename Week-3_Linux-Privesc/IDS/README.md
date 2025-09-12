# 👁️ Intrusion Detection System (IDS) – Python & PyQt5

## 📌 Overview
This project is a **lightweight Intrusion Detection System (IDS)** built in **Python** with a **PyQt5 GUI dashboard**.  
It allows SOC analysts and security researchers to **monitor live network traffic or analyze PCAP files** and **detect malicious activity in real-time**.  
Unlike an IPS, this IDS does **not block traffic** — it focuses on **detection, alerting, and analysis**.

The IDS includes:
- Real-time **packet sniffing** and **rule-based detection**
- An **interactive GUI dashboard** for SOC-style monitoring
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

### 🖥️ GUI Dashboard (PyQt5)
- **Controls Section** → Start/Stop Live Capture, Load/Analyze PCAPs  
- **Threshold Settings** → Adjustable sliders with units (ICMP/SYN thresholds)  
- **Threat Logs** → Timeline of detected threats with severity color coding  
- **Flagged IPs Table** → List of suspicious IPs (with reasons and detection details)  
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
git clone https://github.com/your-username/ids-tool.git
cd ids-tool
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

### Run the IDS GUI

```bash
sudo python3 ids_gui.py
```

> ⚠️ `sudo` (or equivalent permissions) is required for live packet sniffing.

---

## 🔄 Workflow

### 1. Start Live Capture

* Click **Start Live** and enter a network interface (e.g., `eth0`, `wlan0`, `lo`)
* The tool analyzes packets in real-time and raises **alerts** when suspicious activity is detected

### 2. Analyze PCAP Files

* Click **Load PCAP** and choose a `.pcap` or `.pcapng` file
* Click **Analyze PCAP** to replay and detect events from the capture

### 3. Respond to Alerts

* Review **Threat Logs**: time, source IP, threat type, severity, reason
* Inspect **Packet Analysis** (expand the collapsible section)
* Check the **Flagged IPs** table for suspicious IP addresses

### 4. Monitor Graphs

* Charts display **alerts over time**, **threat distribution**, and **flood counts**
* Graphs remain idle until the first suspicious activity is detected

---

## 📂 Project Structure

```bash
IDS/
│── ids_gui.py             # Main IDS GUI application
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
* Flagged IPs table updates automatically with suspicious hosts
* Monitoring charts start updating after the first alert

---

## ⚖️ Limitations

* This is a **lightweight demo IDS** — not a production-grade enterprise solution
* Detection is **rule-based** (no ML/AI yet)
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