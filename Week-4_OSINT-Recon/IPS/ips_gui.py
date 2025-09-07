#!/usr/bin/env python3
"""
ips_gui.py - Integrated IPS GUI with MonitoringCharts from sample (gemini_ips.py)

- Uses the MonitoringCharts class & plotting behavior from your sample file.
- SOC view (left) with Threat Logs, Blocklist, Collapsible Packet Analysis.
- MonitoringCharts (right) idle until first suspicious alert arrives; afterwards updated from real alerts.
- Safe start/stop of sniffer.
"""
import os
import sys
import json
import csv
import threading
from collections import defaultdict
from datetime import datetime, timedelta

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtGui import QColor, QPalette

# import matplotlib-based MonitoringCharts from your sample file (adapted below)
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

# Scapy
from scapy.all import sniff, IP, TCP, ICMP

# Make private runtime dir to avoid XDG warnings and ensure permission
_runtime = "/tmp/ips_gui_runtime"
os.environ["XDG_RUNTIME_DIR"] = _runtime
os.makedirs(_runtime, exist_ok=True)
try:
    os.chmod(_runtime, 0o700)
except Exception:
    pass

# ----------------------------
# MonitoringCharts (from gemini_ips.py, adapted)
# ----------------------------
class MonitoringCharts(QtWidgets.QWidget):
    """
    Matplotlib-based monitoring charts: line (alerts over time), pie, bar.
    Same layout and plotting logic adapted from your sample file.
    The widget exposes update_counters(current_counts, cumulative_counts) to feed real data.
    """
    def __init__(self):
        super().__init__()
        layout = QtWidgets.QVBoxLayout(self)

        # Counters
        self.icmp_total = 0
        self.syn_total = 0
        self.payload_total = 0
        self.tick = 0

        # History deques (for plotting last N points)
        self.max_points = 100
        self.time_data = []
        self.icmp_data = []
        self.syn_data = []
        self.payload_data = []

        # === Line Chart (Alerts over Time) ===
        self.line_group = QtWidgets.QGroupBox("Alerts Over Time")
        line_layout = QtWidgets.QVBoxLayout()
        self.line_group.setLayout(line_layout)
        self.line_fig = Figure(figsize=(6, 2.8))
        self.line_canvas = FigureCanvas(self.line_fig)
        self.line_ax = self.line_fig.add_subplot(111)
        self.line_ax.set_title("Alerts per interval")
        self.line_ax.set_xlabel("Interval")
        self.line_ax.set_ylabel("Count")
        line_layout.addWidget(self.line_canvas)
        layout.addWidget(self.line_group)

        # === Pie Chart (Threat Distribution) ===
        self.pie_group = QtWidgets.QGroupBox("Threat Type Distribution")
        pie_layout = QtWidgets.QVBoxLayout()
        self.pie_group.setLayout(pie_layout)
        self.pie_fig = Figure(figsize=(4, 2))
        self.pie_canvas = FigureCanvas(self.pie_fig)
        self.pie_ax = self.pie_fig.add_subplot(111)
        self.pie_ax.set_title("Threat Distribution (cumulative)")
        pie_layout.addWidget(self.pie_canvas)
        layout.addWidget(self.pie_group)

        # === Bar Chart (Flood counts) ===
        self.bar_group = QtWidgets.QGroupBox("Flood Counts")
        bar_layout = QtWidgets.QVBoxLayout()
        self.bar_group.setLayout(bar_layout)
        self.bar_fig = Figure(figsize=(4, 2))
        self.bar_canvas = FigureCanvas(self.bar_fig)
        self.bar_ax = self.bar_fig.add_subplot(111)
        self.bar_ax.set_title("Flood Counts (ICMP / SYN / Payload)")
        bar_layout.addWidget(self.bar_canvas)
        layout.addWidget(self.bar_group)

        # style
        plt.tight_layout()

    def update_counters(self, current_counts, cumulative_counts):
        """
        Feed the widget with the current interval counts and cumulative counts.
        current_counts: dict with keys 'ICMP Flood', 'SYN Flood', 'Suspicious Payload'
        cumulative_counts: dict with the same keys (totals)
        """
        # update totals from cumulative
        self.icmp_total = int(cumulative_counts.get("ICMP Flood", 0))
        self.syn_total = int(cumulative_counts.get("SYN Flood", 0))
        self.payload_total = int(cumulative_counts.get("Suspicious Payload", 0))

        # add current interval values to history for line chart
        self.tick += 1
        self.time_data.append(self.tick)
        self.icmp_data.append(int(current_counts.get("ICMP Flood", 0)))
        self.syn_data.append(int(current_counts.get("SYN Flood", 0)))
        self.payload_data.append(int(current_counts.get("Suspicious Payload", 0)))

        # trim history
        if len(self.time_data) > self.max_points:
            self.time_data = self.time_data[-self.max_points:]
            self.icmp_data = self.icmp_data[-self.max_points:]
            self.syn_data = self.syn_data[-self.max_points:]
            self.payload_data = self.payload_data[-self.max_points:]

        # ---------- update line chart ----------
        self.line_ax.clear()
        self.line_ax.plot(self.time_data, self.icmp_data, label="ICMP Flood", color='r')
        self.line_ax.plot(self.time_data, self.syn_data, label="SYN Flood", color='orange')
        self.line_ax.plot(self.time_data, self.payload_data, label="Suspicious Payload", color='gold')
        self.line_ax.set_title("Alerts per interval")
        self.line_ax.set_xlabel("Interval")
        self.line_ax.set_ylabel("Count")
        self.line_ax.legend()
        self.line_ax.grid(True)
        self.line_canvas.draw()

        # ---------- update pie chart ----------
        self.pie_ax.clear()
        labels = ["ICMP Flood", "SYN Flood", "Suspicious Payload"]
        sizes = [self.icmp_total, self.syn_total, self.payload_total]
        colors = ['#C80000', '#FF8C00', '#DCDC3C']
        # avoid plotting all zeros
        if sum(sizes) == 0:
            # draw empty pie (single grey slice)
            self.pie_ax.pie([1], labels=["No alerts"], colors=['#DDDDDD'])
        else:
            wedges, texts, autotexts = self.pie_ax.pie(sizes, labels=labels, autopct='%1.0f%%', colors=colors)
            # larger font
            for t in texts + autotexts:
                t.set_fontsize(8)
        self.pie_canvas.draw()

        # ---------- update bar chart ----------
        self.bar_ax.clear()
        labels = ["ICMP", "SYN", "Payload"]
        counts = [self.icmp_total, self.syn_total, self.payload_total]
        colors = ['#C80000', '#FF8C00', '#DCDC3C']
        bars = self.bar_ax.bar(labels, counts, color=colors)
        self.bar_ax.set_ylabel("Total Count")
        self.bar_ax.set_title("Flood Counts")
        # add numeric labels
        for bar in bars:
            height = bar.get_height()
            self.bar_ax.text(bar.get_x() + bar.get_width() / 2, height, f"{height}", ha="center", va="bottom")
        self.bar_canvas.draw()


# ----------------------------
# Sniffer Worker (QThread) - keeps same logic as before
# ----------------------------
class SnifferWorker(QtCore.QThread):
    alert_detected = QtCore.pyqtSignal(dict)

    def __init__(self, iface="lo", thresholds=None, payload_db=None):
        super().__init__()
        self.iface = iface
        self.running = True
        self.thresholds = thresholds or {"icmp": 20, "syn": 50}
        self.payload_db = payload_db or ["' OR 1=1", "<script>", "DROP TABLE"]
        self._icmp_count = 0
        self._syn_count = 0

    def run(self):
        try:
            sniff(iface=self.iface, prn=self._process_packet, store=0,
                  stop_filter=lambda pkt: not self.running)
        except Exception as e:
            self.alert_detected.emit({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src": "0.0.0.0",
                "type": "SnifferError",
                "severity": "High",
                "action": "Error",
                "reason": str(e),
                "payload_snippet": ""
            })

    def _process_packet(self, pkt):
        try:
            if IP not in pkt:
                return
            src = pkt[IP].src

            if pkt.haslayer(ICMP):
                self._icmp_count += 1
                if self._icmp_count > int(self.thresholds.get("icmp", 20)):
                    self._emit_alert(src, "ICMP Flood", "High", "Blocked", "ICMP threshold exceeded")
                    self._icmp_count = 0

            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                is_syn = False
                try:
                    is_syn = (flags == "S")
                except Exception:
                    try:
                        is_syn = bool(int(flags) & 0x02)
                    except Exception:
                        is_syn = False

                if is_syn:
                    self._syn_count += 1
                    if self._syn_count > int(self.thresholds.get("syn", 50)):
                        self._emit_alert(src, "SYN Flood", "High", "Blocked", "SYN threshold exceeded")
                        self._syn_count = 0

                if hasattr(pkt[TCP], "payload") and bytes(pkt[TCP].payload):
                    try:
                        payload = bytes(pkt[TCP].payload).decode(errors="ignore")
                        for patt in self.payload_db:
                            if patt and patt in payload:
                                self._emit_alert(src, "Suspicious Payload", "Medium", "Blocked", f"Pattern: {patt}")
                    except Exception:
                        pass
        except Exception:
            pass

    def _emit_alert(self, src, ttype, severity, action, reason):
        alert = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src": src,
            "type": ttype,
            "severity": severity,
            "action": action,
            "reason": reason,
            "payload_snippet": ""
        }
        self.alert_detected.emit(alert)

    def stop(self):
        self.running = False


# ----------------------------
# Main GUI - merges SOC features with MonitoringCharts
# ----------------------------
class IPSGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IPS GUI")
        self.resize(1400, 820)

        # state
        self.thresholds = {"icmp": 20, "syn": 50}
        self.sniffer_worker = None
        self.payload_db_file = "payload_patterns.json"
        if not os.path.exists(self.payload_db_file):
            with open(self.payload_db_file, "w") as f:
                json.dump(["' OR 1=1", "<script>", "DROP TABLE"], f)
        self.alert_history = []
        self.blocklist = {}
        self.current_counts = defaultdict(int)
        self.cumulative_counts = defaultdict(int)
        self.threat_types = ["ICMP Flood", "SYN Flood", "Suspicious Payload"]

        # UI layout: left SOC, right Monitoring
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_h = QtWidgets.QHBoxLayout()
        central.setLayout(main_h)

        # left SOC
        left_widget = QtWidgets.QWidget()
        left_v = QtWidgets.QVBoxLayout()
        left_widget.setLayout(left_v)
        main_h.addWidget(left_widget, stretch=3)

        # controls and thresholds (compact)
        ctrl_box = QtWidgets.QGroupBox("Controls")
        ctrl_box.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        ctrl_h = QtWidgets.QHBoxLayout()
        ctrl_box.setLayout(ctrl_h)
        self.btn_load_pcap = QtWidgets.QPushButton("Load PCAP")
        self.btn_load_pcap.clicked.connect(self.load_pcap)
        self.btn_live = QtWidgets.QPushButton("Start Live")
        self.btn_live.clicked.connect(self.toggle_live)
        ctrl_h.addWidget(self.btn_load_pcap)
        ctrl_h.addWidget(self.btn_live)
        ctrl_h.addStretch()
        left_v.addWidget(ctrl_box)

        thr_box = QtWidgets.QGroupBox("Thresholds (pkts/interval)")
        thr_box.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        thr_form = QtWidgets.QFormLayout()
        thr_box.setLayout(thr_form)
        self.slider_icmp = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.slider_icmp.setRange(1, 1000)
        self.slider_icmp.setValue(self.thresholds["icmp"])
        self.label_icmp = QtWidgets.QLabel(f"{self.thresholds['icmp']} pkts/interval")
        self.slider_icmp.valueChanged.connect(lambda v: self.label_icmp.setText(f"{v} pkts/interval"))
        thr_form.addRow("ICMP Flood:", self.slider_icmp)
        thr_form.addRow("Value:", self.label_icmp)
        self.slider_syn = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.slider_syn.setRange(1, 1000)
        self.slider_syn.setValue(self.thresholds["syn"])
        self.label_syn = QtWidgets.QLabel(f"{self.thresholds['syn']} pkts/interval")
        self.slider_syn.valueChanged.connect(lambda v: self.label_syn.setText(f"{v} pkts/interval"))
        thr_form.addRow("SYN Flood:", self.slider_syn)
        thr_form.addRow("Value:", self.label_syn)
        left_v.addWidget(thr_box)

        # logs table
        left_v.addWidget(QtWidgets.QLabel("Threat Logs"))
        self.logs_table = QtWidgets.QTableWidget(0, 6)
        self.logs_table.setHorizontalHeaderLabels(["Time", "IP", "Type", "Severity", "Action", "Reason"])
        self.logs_table.horizontalHeader().setStretchLastSection(True)
        self.logs_table.cellClicked.connect(self.on_log_clicked)
        self.logs_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.logs_table.customContextMenuRequested.connect(self.logs_context_menu)
        left_v.addWidget(self.logs_table, stretch=4)

        # blocklist
        left_v.addWidget(QtWidgets.QLabel("Blocklist"))
        self.block_table = QtWidgets.QTableWidget(0, 3)
        self.block_table.setHorizontalHeaderLabels(["IP", "Unblock Time", "Reason"])
        self.block_table.horizontalHeader().setStretchLastSection(True)
        self.block_table.cellClicked.connect(self.on_block_clicked)
        self.block_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.block_table.customContextMenuRequested.connect(self.block_context_menu)
        left_v.addWidget(self.block_table, stretch=1)

        # collapsible packet analysis
        self.pa_toggle = QtWidgets.QPushButton("Show Packet Analysis ▼")
        self.pa_toggle.setCheckable(True)
        self.pa_toggle.clicked.connect(self._toggle_packet_analysis)
        left_v.addWidget(self.pa_toggle)
        self.pa_widget = QtWidgets.QWidget()
        self.pa_widget.setVisible(False)
        pa_v = QtWidgets.QVBoxLayout()
        self.pa_widget.setLayout(pa_v)
        self.packet_text = QtWidgets.QTextEdit()
        self.packet_text.setReadOnly(True)
        pa_v.addWidget(self.packet_text)
        left_v.addWidget(self.pa_widget, stretch=1)

        # bottom row: dark mode + clear filter
        bottom_row = QtWidgets.QHBoxLayout()
        self.dark_check = QtWidgets.QCheckBox("Dark Mode")
        self.dark_check.stateChanged.connect(self.toggle_dark)
        bottom_row.addWidget(self.dark_check)
        bottom_row.addStretch()
        self.btn_clear = QtWidgets.QPushButton("Clear Log Filter")
        self.btn_clear.clicked.connect(self.clear_log_filter)
        bottom_row.addWidget(self.btn_clear)
        left_v.addLayout(bottom_row)

        # right MonitoringCharts (from sample)
        self.monitor = MonitoringCharts()
        main_h.addWidget(self.monitor, stretch=2)

        # timer to push current_counts -> monitoring (only if monitoring_active)
        self.monitor_active = False
        self.push_timer = QtCore.QTimer()
        self.push_timer.timeout.connect(self._push_counts_to_monitor)
        self.push_timer.start(1000)  # every second

    # ---------- UI actions ----------
    def _toggle_packet_analysis(self, checked):
        if checked:
            self.pa_widget.setVisible(True)
            self.pa_toggle.setText("Hide Packet Analysis ▲")
        else:
            self.pa_widget.setVisible(False)
            self.pa_toggle.setText("Show Packet Analysis ▼")

    def load_pcap(self):
        fn, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load PCAP", "", "PCAP files (*.pcap)")
        if fn:
            QtWidgets.QMessageBox.information(self, "PCAP", f"Loaded {fn} (demo)")

    def toggle_live(self):
        if self.sniffer_worker is None:
            iface, ok = QtWidgets.QInputDialog.getText(self, "Interface", "Enter interface (e.g., lo):")
            if not ok or not iface.strip():
                return
            self.thresholds["icmp"] = int(self.slider_icmp.value())
            self.thresholds["syn"] = int(self.slider_syn.value())
            try:
                payload_db = json.load(open(self.payload_db_file))
            except Exception:
                payload_db = ["' OR 1=1", "<script>", "DROP TABLE"]
            self.sniffer_worker = SnifferWorker(iface=iface.strip(), thresholds=self.thresholds, payload_db=payload_db)
            self.sniffer_worker.alert_detected.connect(self._handle_alert)
            self.sniffer_worker.start()
            self.btn_live.setText("Stop Live")
        else:
            try:
                self.sniffer_worker.stop()
                self.sniffer_worker.wait(timeout=3000)
            except Exception:
                pass
            self.sniffer_worker = None
            self.btn_live.setText("Start Live")

    # ---------- alert handling ----------
    def _handle_alert(self, alert):
        # record
        self.alert_history.append(alert)
        try:
            with open("alert_history.json", "w") as f:
                json.dump(self.alert_history, f, indent=2)
            with open("alert_history.csv", "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=alert.keys())
                writer.writeheader()
                writer.writerows(self.alert_history)
        except Exception:
            pass

        # logs
        r = self.logs_table.rowCount()
        self.logs_table.insertRow(r)
        self.logs_table.setItem(r, 0, QtWidgets.QTableWidgetItem(alert["time"]))
        self.logs_table.setItem(r, 1, QtWidgets.QTableWidgetItem(alert["src"]))
        self.logs_table.setItem(r, 2, QtWidgets.QTableWidgetItem(alert["type"]))
        self.logs_table.setItem(r, 3, QtWidgets.QTableWidgetItem(alert["severity"]))
        self.logs_table.setItem(r, 4, QtWidgets.QTableWidgetItem(alert["action"]))
        self.logs_table.setItem(r, 5, QtWidgets.QTableWidgetItem(alert["reason"]))

        color = QColor(255, 255, 153)
        if alert["severity"] == "High":
            color = QColor(255, 102, 102)
        elif alert["severity"] == "Medium":
            color = QColor(255, 178, 102)
        for c in range(6):
            item = self.logs_table.item(r, c)
            if item:
                item.setBackground(color)

        # blocklist auto add
        ip = alert["src"]
        if ip not in self.blocklist:
            unblock = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            self.blocklist[ip] = {"unblock": unblock, "reason": alert["reason"]}
            br = self.block_table.rowCount()
            self.block_table.insertRow(br)
            self.block_table.setItem(br, 0, QtWidgets.QTableWidgetItem(ip))
            self.block_table.setItem(br, 1, QtWidgets.QTableWidgetItem(unblock))
            self.block_table.setItem(br, 2, QtWidgets.QTableWidgetItem(alert["reason"]))

        # update counters
        t = alert.get("type")
        if t:
            self.current_counts[t] += 1
            self.cumulative_counts[t] += 1

        # enable monitoring on first suspicious alert
        if t in self.threat_types and not self.monitor_active:
            self.monitor_active = True

    def _push_counts_to_monitor(self):
        if not self.monitor_active:
            return
        # feed current counts and cumulative to monitor widget
        self.monitor.update_counters(self.current_counts, self.cumulative_counts)
        # reset current counts
        self.current_counts = defaultdict(int)

    # ---------- UI interactions ----------
    def on_log_clicked(self, row, _col):
        try:
            time_s = self.logs_table.item(row, 0).text()
            ip = self.logs_table.item(row, 1).text()
            t = self.logs_table.item(row, 2).text()
            sev = self.logs_table.item(row, 3).text()
            action = self.logs_table.item(row, 4).text()
            reason = self.logs_table.item(row, 5).text()
        except Exception:
            return
        report = (
            f"--- General Info ---\n"
            f"Time: {time_s}\n"
            f"Source IP: {ip}\n"
            f"Threat Type: {t}\n"
            f"Severity: {sev}\n\n"
            f"--- Action Info ---\n"
            f"Action Taken: {action}\n"
            f"Reason: {reason}\n\n"
            f"--- Payload / Notes ---\n"
            f"Payload: (not captured)\n"
        )
        self.packet_text.setPlainText(report)
        # auto-expand packet analysis
        if not self.pa_widget.isVisible():
            self.pa_toggle.setChecked(True)
            self._toggle_packet_analysis(True)

    def on_block_clicked(self, row, _col):
        try:
            ip = self.block_table.item(row, 0).text()
        except Exception:
            return
        info = self.blocklist.get(ip, {})
        report = (
            f"--- Blocked IP Info ---\n"
            f"IP: {ip}\n"
            f"Unblock time: {info.get('unblock','N/A')}\n"
            f"Reason: {info.get('reason','N/A')}\n"
        )
        self.packet_text.setPlainText(report)

    def logs_context_menu(self, pos):
        menu = QtWidgets.QMenu()
        clear = menu.addAction("Clear Log Filter")
        unblock = menu.addAction("Unblock IP (selected row)")
        act = menu.exec_(self.logs_table.viewport().mapToGlobal(pos))
        if act == clear:
            self.clear_log_filter()
        elif act == unblock:
            row = self.logs_table.currentRow()
            if row >= 0:
                ip = self.logs_table.item(row, 1).text()
                self._unblock_ip(ip)

    def block_context_menu(self, pos):
        menu = QtWidgets.QMenu()
        unblock = menu.addAction("Unblock IP")
        act = menu.exec_(self.block_table.viewport().mapToGlobal(pos))
        if act == unblock:
            row = self.block_table.currentRow()
            if row >= 0:
                ip = self.block_table.item(row, 0).text()
                self._unblock_ip(ip)

    def _unblock_ip(self, ip):
        if ip in self.blocklist:
            del self.blocklist[ip]
            for r in range(self.block_table.rowCount()):
                if self.block_table.item(r, 0).text() == ip:
                    self.block_table.removeRow(r)
                    break

    def filter_logs_by_type(self, ttype):
        for r in range(self.logs_table.rowCount()):
            item = self.logs_table.item(r, 2)
            if item:
                self.logs_table.setRowHidden(r, item.text() != ttype)

    def clear_log_filter(self):
        for r in range(self.logs_table.rowCount()):
            self.logs_table.setRowHidden(r, False)

    def toggle_dark(self, state):
        pal = QPalette()
        if state == QtCore.Qt.Checked:
            pal.setColor(QPalette.Window, QColor(53, 53, 53))
            pal.setColor(QPalette.WindowText, QtCore.Qt.white)
            pal.setColor(QPalette.Base, QColor(25, 25, 25))
            pal.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            pal.setColor(QPalette.ToolTipBase, QtCore.Qt.white)
            pal.setColor(QPalette.ToolTipText, QtCore.Qt.white)
            pal.setColor(QPalette.Text, QtCore.Qt.white)
            pal.setColor(QPalette.Button, QColor(53, 53, 53))
            pal.setColor(QPalette.ButtonText, QtCore.Qt.white)
            pal.setColor(QPalette.Highlight, QColor(142, 45, 197).lighter())
            pal.setColor(QPalette.HighlightedText, QtCore.Qt.black)
        else:
            pal = QtWidgets.QApplication.style().standardPalette()
        QtWidgets.QApplication.instance().setPalette(pal)


# ----------------------------
# Run app
# ----------------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    gui = IPSGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
