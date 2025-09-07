#!/usr/bin/env python3
"""
ids_gui.py - GUI IDS Tool (clean, fixed)

Features:
- Live capture + PCAP analysis
- Detects ICMP/SYN floods, Port Scans, Repeated Port Attempts, Suspicious Payloads
- Threat logs with alert details (Detected)
- Flagged IPs table (informational only)
- Collapsible Packet Analysis panel
- Monitoring charts (matplotlib) that remain idle until first detection
- Threshold sliders with units
- Dark mode toggle
- Alert persistence to JSON + CSV
"""
import os
import sys
import json
import csv
from datetime import datetime
from collections import defaultdict, deque

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtCore import Qt

# Matplotlib embedding
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# Scapy (for live capture and pcap reading)
from scapy.all import sniff, IP, TCP, ICMP, Raw, rdpcap


# ----------------------------
# MonitoringCharts (matplotlib)
# ----------------------------
class MonitoringCharts(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.max_points = 120
        self.tick = 0

        # histories
        self.x = deque(maxlen=self.max_points)
        self.icmp_hist = deque(maxlen=self.max_points)
        self.syn_hist = deque(maxlen=self.max_points)
        self.payload_hist = deque(maxlen=self.max_points)

        # cumulative totals
        self.cum = {"ICMP Flood": 0, "SYN Flood": 0, "Suspicious Payload": 0}

        layout = QtWidgets.QVBoxLayout(self)

        # Line chart
        self.line_group = QtWidgets.QGroupBox("Alerts over time")
        line_layout = QtWidgets.QVBoxLayout(self.line_group)
        self.line_fig = Figure(figsize=(6, 2.6))
        self.line_canvas = FigureCanvas(self.line_fig)
        self.line_ax = self.line_fig.add_subplot(111)
        line_layout.addWidget(self.line_canvas)
        layout.addWidget(self.line_group)

        # Pie chart
        self.pie_group = QtWidgets.QGroupBox("Threat distribution")
        pie_layout = QtWidgets.QVBoxLayout(self.pie_group)
        self.pie_fig = Figure(figsize=(4, 2))
        self.pie_canvas = FigureCanvas(self.pie_fig)
        self.pie_ax = self.pie_fig.add_subplot(111)
        pie_layout.addWidget(self.pie_canvas)
        layout.addWidget(self.pie_group)

        # Bar chart
        self.bar_group = QtWidgets.QGroupBox("Flood counts (cumulative)")
        bar_layout = QtWidgets.QVBoxLayout(self.bar_group)
        self.bar_fig = Figure(figsize=(4, 2))
        self.bar_canvas = FigureCanvas(self.bar_fig)
        self.bar_ax = self.bar_fig.add_subplot(111)
        bar_layout.addWidget(self.bar_canvas)
        layout.addWidget(self.bar_group)

        # charts idle until activated
        self.active = False

    def activate(self):
        self.active = True

    def update_from_counts(self, current_counts, cumulative_counts):
        """
        Push current interval counts and cumulative counts to charts.
        current_counts & cumulative_counts are dicts keyed by threat type.
        """
        if not self.active:
            self.activate()

        self.tick += 1
        self.x.append(self.tick)
        self.icmp_hist.append(current_counts.get("ICMP Flood", 0))
        self.syn_hist.append(current_counts.get("SYN Flood", 0))
        self.payload_hist.append(current_counts.get("Suspicious Payload", 0))

        # update cumulative snapshot
        for k in self.cum.keys():
            self.cum[k] = int(cumulative_counts.get(k, 0))

        # update line chart
        self.line_ax.clear()
        self.line_ax.plot(list(self.x), list(self.icmp_hist), label="ICMP Flood", color="#C80000")
        self.line_ax.plot(list(self.x), list(self.syn_hist), label="SYN Flood", color="#FF8C00")
        self.line_ax.plot(list(self.x), list(self.payload_hist), label="Suspicious Payload", color="#DCDC3C")
        self.line_ax.set_xlabel("Interval")
        self.line_ax.set_ylabel("Count")
        self.line_ax.legend(loc="upper left", fontsize="small")
        self.line_ax.grid(True)
        self.line_canvas.draw_idle()

        # update pie chart
        self.pie_ax.clear()
        labels = list(self.cum.keys())
        sizes = [self.cum[l] for l in labels]
        colors = ["#C80000", "#FF8C00", "#DCDC3C"]
        if sum(sizes) == 0:
            self.pie_ax.pie([1], labels=["No alerts"], colors=["#DDDDDD"])
        else:
            self.pie_ax.pie(sizes, labels=labels, autopct="%1.0f%%", colors=colors)
        self.pie_canvas.draw_idle()

        # update bar chart
        self.bar_ax.clear()
        labels_short = ["ICMP", "SYN", "Payload"]
        counts = [self.cum["ICMP Flood"], self.cum["SYN Flood"], self.cum["Suspicious Payload"]]
        bars = self.bar_ax.bar(labels_short, counts, color=colors)
        for bar in bars:
            h = bar.get_height()
            self.bar_ax.text(bar.get_x() + bar.get_width() / 2.0, h, f"{int(h)}", ha="center", va="bottom", fontsize=8)
        self.bar_ax.set_ylabel("Total")
        self.bar_canvas.draw_idle()


# ----------------------------
# Detector logic
# ----------------------------
class Detector:
    def __init__(self, thresholds=None, payload_patterns=None):
        self.thresholds = thresholds or {"icmp": 20, "syn": 50}
        self.payload_patterns = payload_patterns or ["' OR 1=1", "<script>", "DROP TABLE"]
        # interval counters per src
        self.icmp_counts = defaultdict(int)
        self.syn_counts = defaultdict(int)
        self.port_history = defaultdict(lambda: defaultdict(int))
        self.repeated_attempts = defaultdict(lambda: defaultdict(int))

    def process_packet(self, pkt, emit_alert_fn):
        """Analyze a scapy packet and call emit_alert_fn(alert_dict) on detection."""
        try:
            if IP not in pkt:
                return
            src = pkt[IP].src

            # ICMP flood detection
            if pkt.haslayer(ICMP):
                self.icmp_counts[src] += 1
                if self.icmp_counts[src] > int(self.thresholds.get("icmp", 20)):
                    emit_alert_fn(self._make_alert(src, "ICMP Flood", "High", "Detected", "ICMP threshold exceeded"))
                    self.icmp_counts[src] = 0

            # TCP analysis
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                is_syn = False
                try:
                    is_syn = (str(flags) == "S")
                except Exception:
                    try:
                        is_syn = bool(int(flags) & 0x02)
                    except Exception:
                        is_syn = False

                if is_syn:
                    self.syn_counts[src] += 1
                    if self.syn_counts[src] > int(self.thresholds.get("syn", 50)):
                        emit_alert_fn(self._make_alert(src, "SYN Flood", "High", "Detected", "SYN threshold exceeded"))
                        self.syn_counts[src] = 0

                # port scan heuristic and repeated attempts
                dport = getattr(pkt[TCP], "dport", None)
                if dport is not None:
                    self.port_history[src][dport] += 1
                    if len(self.port_history[src]) >= 10:
                        emit_alert_fn(self._make_alert(src, "Port Scan", "Medium", "Detected", "Multiple ports probed"))
                        self.port_history[src].clear()

                    self.repeated_attempts[src][dport] += 1
                    if self.repeated_attempts[src][dport] > 8:
                        emit_alert_fn(self._make_alert(src, "Repeated Port Attempts", "Medium", "Detected", f"Repeated attempts to port {dport}"))
                        self.repeated_attempts[src][dport] = 0

                # payload pattern checks
                if pkt.haslayer(Raw):
                    try:
                        payload = bytes(pkt[Raw].load).decode(errors="ignore")
                        for patt in self.payload_patterns:
                            if patt and patt in payload:
                                emit_alert_fn(self._make_alert(src, "Suspicious Payload", "Medium", "Detected", f"Pattern: {patt}"))
                    except Exception:
                        pass

        except Exception:
            # fail-safe: ignore parsing errors
            pass

    def reset_interval_counters(self):
        self.icmp_counts.clear()
        self.syn_counts.clear()
        self.port_history.clear()
        self.repeated_attempts.clear()

    @staticmethod
    def _make_alert(src, ttype, severity, action, reason):
        return {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src": src,
            "type": ttype,
            "severity": severity,
            "action": action,
            "reason": reason
        }


# ----------------------------
# Worker threads
# ----------------------------
class LiveSniffer(QtCore.QThread):
    alert_signal = QtCore.pyqtSignal(dict)

    def __init__(self, iface, detector):
        super().__init__()
        self.iface = iface
        self.detector = detector
        self.running = True

    def run(self):
        try:
            sniff(iface=self.iface, prn=lambda p: self.detector.process_packet(p, self.alert_signal.emit),
                  store=0, stop_filter=lambda p: not self.running)
        except Exception as e:
            # report error to GUI
            self.alert_signal.emit({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src": "0.0.0.0",
                "type": "SnifferError",
                "severity": "High",
                "action": "Error",
                "reason": str(e)
            })

    def stop(self):
        self.running = False


class PcapProcessor(QtCore.QThread):
    alert_signal = QtCore.pyqtSignal(dict)
    finished_signal = QtCore.pyqtSignal()

    def __init__(self, path, detector):
        super().__init__()
        self.path = path
        self.detector = detector
        self._stop = False

    def run(self):
        try:
            pkts = rdpcap(self.path)
        except Exception as e:
            self.alert_signal.emit({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src": "0.0.0.0",
                "type": "PcapError",
                "severity": "High",
                "action": "Error",
                "reason": str(e)
            })
            self.finished_signal.emit()
            return

        for pkt in pkts:
            if self._stop:
                break
            self.detector.process_packet(pkt, self.alert_signal.emit)
            QtCore.QThread.msleep(1)

        self.finished_signal.emit()

    def stop(self):
        self._stop = True


# ----------------------------
# Main GUI
# ----------------------------
class IDSGui(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS GUI")
        self.resize(1300, 820)

        # state
        self.detector = Detector()
        self.live_worker = None
        self.pcap_worker = None
        self.alert_history = []
        self.flagged_ips = {}
        self.current_counts = defaultdict(int)
        self.cumulative_counts = defaultdict(int)
        self.monitoring_active = False
        self.loaded_pcap = None

        # payload patterns file
        self.payload_db_file = "payload_patterns.json"
        if not os.path.exists(self.payload_db_file):
            with open(self.payload_db_file, "w") as f:
                json.dump(["' OR 1=1", "<script>", "DROP TABLE"], f)

        # layout: left (SOC) and right (Monitoring)
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_h = QtWidgets.QHBoxLayout()
        central.setLayout(main_h)

        # left column
        left_widget = QtWidgets.QWidget()
        left_v = QtWidgets.QVBoxLayout()
        left_widget.setLayout(left_v)
        main_h.addWidget(left_widget, stretch=3)

        # controls
        ctrl_box = QtWidgets.QGroupBox("Controls")
        ctrl_layout = QtWidgets.QHBoxLayout()
        ctrl_box.setLayout(ctrl_layout)
        self.btn_load_pcap = QtWidgets.QPushButton("Load PCAP")
        self.btn_load_pcap.clicked.connect(self.load_pcap)
        self.btn_analyze_pcap = QtWidgets.QPushButton("Analyze PCAP")
        self.btn_analyze_pcap.clicked.connect(self.analyze_pcap)
        self.btn_live = QtWidgets.QPushButton("Start Live")
        self.btn_live.clicked.connect(self.toggle_live)
        ctrl_layout.addWidget(self.btn_load_pcap)
        ctrl_layout.addWidget(self.btn_analyze_pcap)
        ctrl_layout.addWidget(self.btn_live)
        ctrl_layout.addStretch()
        left_v.addWidget(ctrl_box)

        # thresholds
        thr_box = QtWidgets.QGroupBox("Thresholds (pkts / interval)")
        thr_layout = QtWidgets.QFormLayout()
        thr_box.setLayout(thr_layout)
        self.slider_icmp = QtWidgets.QSlider(Qt.Horizontal)
        self.slider_icmp.setRange(1, 1000)
        self.slider_icmp.setValue(20)
        self.label_icmp = QtWidgets.QLabel("20 pkts/interval")
        self.slider_icmp.valueChanged.connect(lambda v: self.label_icmp.setText(f"{v} pkts/interval"))
        thr_layout.addRow("ICMP Flood:", self.slider_icmp)
        thr_layout.addRow("Value:", self.label_icmp)

        self.slider_syn = QtWidgets.QSlider(Qt.Horizontal)
        self.slider_syn.setRange(1, 1000)
        self.slider_syn.setValue(50)
        self.label_syn = QtWidgets.QLabel("50 pkts/interval")
        self.slider_syn.valueChanged.connect(lambda v: self.label_syn.setText(f"{v} pkts/interval"))
        thr_layout.addRow("SYN Flood:", self.slider_syn)
        thr_layout.addRow("Value:", self.label_syn)

        left_v.addWidget(thr_box)

        # threat logs
        left_v.addWidget(QtWidgets.QLabel("Threat Logs"))
        self.logs_table = QtWidgets.QTableWidget(0, 6)
        self.logs_table.setHorizontalHeaderLabels(["Time", "IP", "Type", "Severity", "Action", "Reason"])
        self.logs_table.horizontalHeader().setStretchLastSection(True)
        self.logs_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.logs_table.cellClicked.connect(self.on_log_row_clicked)
        left_v.addWidget(self.logs_table, stretch=4)

        # flagged IPs (informational)
        left_v.addWidget(QtWidgets.QLabel("Flagged IPs"))
        self.flag_table = QtWidgets.QTableWidget(0, 3)
        self.flag_table.setHorizontalHeaderLabels(["IP", "Count", "Last Seen"])
        self.flag_table.horizontalHeader().setStretchLastSection(True)
        left_v.addWidget(self.flag_table, stretch=1)

        # collapsible packet analysis
        self.pa_toggle = QtWidgets.QPushButton("Show Packet Analysis ▼")
        self.pa_toggle.setCheckable(True)
        self.pa_toggle.clicked.connect(self.toggle_packet_analysis)
        left_v.addWidget(self.pa_toggle)
        self.pa_widget = QtWidgets.QWidget()
        self.pa_widget.setVisible(False)
        pa_layout = QtWidgets.QVBoxLayout()
        self.pa_widget.setLayout(pa_layout)
        self.packet_analysis_text = QtWidgets.QTextEdit()
        self.packet_analysis_text.setReadOnly(True)
        pa_layout.addWidget(self.packet_analysis_text)
        left_v.addWidget(self.pa_widget, stretch=1)

        # bottom row: dark mode + clear filter
        bottom_layout = QtWidgets.QHBoxLayout()
        self.dark_mode = QtWidgets.QCheckBox("Dark Mode")
        self.dark_mode.stateChanged.connect(self.toggle_dark)
        bottom_layout.addWidget(self.dark_mode)
        bottom_layout.addStretch()
        self.btn_clear_filter = QtWidgets.QPushButton("Clear Log Filter")
        self.btn_clear_filter.clicked.connect(self.clear_log_filter)
        bottom_layout.addWidget(self.btn_clear_filter)
        left_v.addLayout(bottom_layout)

        # right monitoring
        self.monitor = MonitoringCharts()
        main_h.addWidget(self.monitor, stretch=2)

        # timer to push counts to monitor every second
        self.monitor_timer = QtCore.QTimer()
        self.monitor_timer.timeout.connect(self._monitor_tick)
        self.monitor_timer.start(1000)

    # ----------------- UI Actions -----------------
    def toggle_packet_analysis(self):
        if self.pa_toggle.isChecked():
            self.pa_toggle.setText("Hide Packet Analysis ▲")
            self.pa_widget.setVisible(True)
        else:
            self.pa_toggle.setText("Show Packet Analysis ▼")
            self.pa_widget.setVisible(False)

    def load_pcap(self):
        fn, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open PCAP", "", "PCAP files (*.pcap *.pcapng)")
        if fn:
            self.loaded_pcap = fn
            QtWidgets.QMessageBox.information(self, "PCAP loaded", f"{fn}")
        else:
            self.loaded_pcap = None

    def analyze_pcap(self):
        if not hasattr(self, "loaded_pcap") or not self.loaded_pcap:
            QtWidgets.QMessageBox.warning(self, "No PCAP", "Please load a PCAP file first.")
            return
        # update detector configuration
        self.update_detector()
        # stop any running pcap worker
        if self.pcap_worker and self.pcap_worker.isRunning():
            self.pcap_worker.stop()
            self.pcap_worker.wait()
        self.pcap_worker = PcapProcessor(self.loaded_pcap, self.detector)
        self.pcap_worker.alert_signal.connect(self.handle_alert)
        self.pcap_worker.finished_signal.connect(lambda: QtWidgets.QMessageBox.information(self, "PCAP", "PCAP analysis finished"))
        self.pcap_worker.start()

    def toggle_live(self):
        if self.live_worker is None:
            iface, ok = QtWidgets.QInputDialog.getText(self, "Interface", "Interface (e.g., lo):")
            if not ok or not iface.strip():
                return
            # update detector and start live worker
            self.update_detector()
            self.live_worker = LiveSniffer(iface.strip(), self.detector)
            self.live_worker.alert_signal.connect(self.handle_alert)
            self.live_worker.start()
            self.btn_live.setText("Stop Live")
        else:
            # stop live worker safely
            try:
                self.live_worker.stop()
                self.live_worker.wait(timeout=3000)
            except Exception:
                pass
            self.live_worker = None
            self.btn_live.setText("Start Live")

    def update_detector(self):
        # update detector instance with UI thresholds and payload db
        thresholds = {"icmp": int(self.slider_icmp.value()), "syn": int(self.slider_syn.value())}
        try:
            patterns = json.load(open(self.payload_db_file))
        except Exception:
            patterns = ["' OR 1=1", "<script>", "DROP TABLE"]
        self.detector = Detector(thresholds=thresholds, payload_patterns=patterns)

    # ----------------- Alert handling -----------------
    def handle_alert(self, alert):
        # normalize action to "Detected"
        alert["action"] = "Detected"

        # append history and persist
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

        # add to logs table
        r = self.logs_table.rowCount()
        self.logs_table.insertRow(r)
        cols = ["time", "src", "type", "severity", "action", "reason"]
        for i, key in enumerate(cols):
            item = QtWidgets.QTableWidgetItem(str(alert.get(key, "")))
            self.logs_table.setItem(r, i, item)

        # color by severity
        color = QColor(255, 255, 153)
        if alert.get("severity") == "High":
            color = QColor(255, 102, 102)
        elif alert.get("severity") == "Medium":
            color = QColor(255, 178, 102)
        for c in range(6):
            it = self.logs_table.item(r, c)
            if it:
                it.setBackground(color)

        # flagged IPs update
        ip = alert.get("src", "")
        info = self.flagged_ips.get(ip, {"count": 0, "last": ""})
        info["count"] = info.get("count", 0) + 1
        info["last"] = alert.get("time")
        self.flagged_ips[ip] = info
        self.refresh_flag_table()

        # update monitoring counters
        t = alert.get("type")
        if t in ("ICMP Flood", "SYN Flood", "Suspicious Payload"):
            self.current_counts[t] += 1
            self.cumulative_counts[t] += 1
            if not self.monitoring_active:
                self.monitoring_active = True
                self.monitor.activate()

    def refresh_flag_table(self):
        # rebuild flagged IPs table
        self.flag_table.setRowCount(0)
        for ip, info in self.flagged_ips.items():
            r = self.flag_table.rowCount()
            self.flag_table.insertRow(r)
            self.flag_table.setItem(r, 0, QtWidgets.QTableWidgetItem(ip))
            self.flag_table.setItem(r, 1, QtWidgets.QTableWidgetItem(str(info.get("count", 0))))
            self.flag_table.setItem(r, 2, QtWidgets.QTableWidgetItem(str(info.get("last", ""))))

    # ----------------- Monitoring tick -----------------
    def _monitor_tick(self):
        if not self.monitoring_active:
            return
        # ensure keys exist
        for k in ("ICMP Flood", "SYN Flood", "Suspicious Payload"):
            self.current_counts.setdefault(k, 0)
            self.cumulative_counts.setdefault(k, 0)
        # push to monitor
        self.monitor.update_from_counts(self.current_counts, self.cumulative_counts)
        # reset current counts and detector interval counters
        self.current_counts = defaultdict(int)
        try:
            self.detector.reset_interval_counters()
        except Exception:
            pass

    # ----------------- UI interactions -----------------
    def on_log_row_clicked(self, row, _col):
        try:
            time_s = self.logs_table.item(row, 0).text()
            ip = self.logs_table.item(row, 1).text()
            ttype = self.logs_table.item(row, 2).text()
            severity = self.logs_table.item(row, 3).text()
            action = self.logs_table.item(row, 4).text()
            reason = self.logs_table.item(row, 5).text()
        except Exception:
            return
        report = (
            f"--- General Info ---\n"
            f"Time: {time_s}\n"
            f"Source IP: {ip}\n"
            f"Threat Type: {ttype}\n"
            f"Severity: {severity}\n\n"
            f"--- Action Info ---\n"
            f"Action Taken: {action}\n"
            f"Reason: {reason}\n\n"
            f"--- Payload / Notes ---\n"
            f"Payload: (not captured)\n"
        )
        self.packet_analysis_text.setPlainText(report)
        if not self.pa_widget.isVisible():
            self.pa_toggle.setChecked(True)
            self.pa_widget.setVisible(True)
            self.pa_toggle.setText("Hide Packet Analysis ▲")

    def clear_log_filter(self):
        for r in range(self.logs_table.rowCount()):
            self.logs_table.setRowHidden(r, False)

    def toggle_dark(self, state):
        palette = QPalette()
        if state == Qt.Checked:
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, QtCore.Qt.white)
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.Text, QtCore.Qt.white)
        else:
            palette = QtWidgets.QApplication.style().standardPalette()
        QtWidgets.QApplication.instance().setPalette(palette)

    # simple context menus (no unblock)
    def logs_context_menu(self, pos):
        menu = QtWidgets.QMenu()
        clear = menu.addAction("Clear Log Filter")
        action = menu.exec_(self.logs_table.viewport().mapToGlobal(pos))
        if action == clear:
            self.clear_log_filter()

# Run
# ----------------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    gui = IDSGui()
    gui.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
