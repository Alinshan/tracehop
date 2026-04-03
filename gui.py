import sys
import os
import json
import asyncio
import threading
from datetime import datetime
from PySide6 import QtCore, QtGui, QtWidgets
from scanner.engine import TracehopEngine
from scanner.pentester import PentestEngine

class WatermarkPlainTextEdit(QtWidgets.QPlainTextEdit):
    def __init__(self, watermark_text, parent=None):
        super().__init__(parent)
        self.watermark_text = watermark_text
        self.setStyleSheet("background: transparent; color: #00ff00; font-family: Consolas; border: none;")

    def paintEvent(self, event):
        painter = QtGui.QPainter(self.viewport())
        painter.setRenderHint(QtGui.QPainter.TextAntialiasing)
        
        # Very subtle shadow color for the watermark
        painter.setPen(QtGui.QColor(35, 35, 35)) 
        font = QtGui.QFont("Consolas", 14)
        painter.setFont(font)
        
        # Draw the watermark centered
        rect = self.viewport().rect()
        painter.drawText(rect, QtCore.Qt.AlignCenter, self.watermark_text)
        painter.end()
        
        super().paintEvent(event)

class ScanWorker(QtCore.QObject):
    finished = QtCore.Signal(list, dict, str) # results, recon_data, report_path
    progress = QtCore.Signal(str)
    
    def __init__(self, target, threads, rules_path=None, ua_path=None, pentest=False):
        super().__init__()
        self.target = target
        self.threads = threads
        self.rules_path = rules_path
        self.ua_path = ua_path
        self.pentest = pentest
        self.loop = None

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Load User Agents
        user_agents = []
        if self.ua_path and os.path.exists(self.ua_path):
            with open(self.ua_path, 'r') as f:
                user_agents = [line.strip() for line in f if line.strip()]

        try:
            if self.pentest:
                self.progress.emit("Starting Advanced Pentest Suite...")
                p_engine = PentestEngine(self.target, custom_rules_path=self.rules_path, user_agents=user_agents)
                
                vulns, report_path = self.loop.run_until_complete(p_engine.execute_suite(progress_callback=self.progress.emit))
                results = p_engine.main_engine.results
                recon_data = p_engine.main_engine.recon_data
                self.finished.emit(results, recon_data, report_path)
            else:
                self.progress.emit(f"Initializing Phase 0: Technical Intelligence on {self.target}...")
                engine = TracehopEngine(self.target, semaphore_limit=self.threads, 
                                        custom_rules_path=self.rules_path, 
                                        user_agents=user_agents)
                
                # Phase 0
                self.loop.run_until_complete(engine.run_reconnaissance())
                
                # Phase 1+
                self.progress.emit("Proceeding to Phase 1: JS Recon & Secret Scanning...")
                results = self.loop.run_until_complete(engine.run(enumerate_subdomains=True, 
                                                               progress_callback=self.progress.emit))
                self.finished.emit(results, engine.recon_data, "")
        except Exception as e:
            self.progress.emit(f"Error: {str(e)}")
            self.finished.emit([], {}, "")

class TracehopGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Tracehop | Automated JS Recon & Pentest")
        self.resize(1100, 750)
        self.setup_ui()
        self.apply_dark_theme()

    def setup_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QHBoxLayout(central)

        # --- Sidebar (Settings) ---
        sidebar = QtWidgets.QFrame()
        sidebar.setFixedWidth(300)
        sidebar.setFrameShape(QtWidgets.QFrame.StyledPanel)
        sidebar_layout = QtWidgets.QVBoxLayout(sidebar)

        # Hacker Cat ASCII Art
        cat_ascii = r"""
   | \__/,|   (`\
 _.|o o  |_   ) )
-(((---(((--------
        """
        cat_label = QtWidgets.QLabel(cat_ascii)
        cat_label.setStyleSheet("color: #00b0ff; font-family: 'Consolas', 'Courier New'; font-size: 10px; margin-bottom: -10px;")
        cat_label.setAlignment(QtCore.Qt.AlignCenter)
        sidebar_layout.addWidget(cat_label)

        # Sidebar Header
        header = QtWidgets.QLabel("TRACEHOP")
        header.setStyleSheet("color: #00b0ff; font-weight: bold; font-size: 24px; margin-bottom: 5px;")
        header.setAlignment(QtCore.Qt.AlignCenter)
        sidebar_layout.addWidget(header)

        version_label = QtWidgets.QLabel("v3.1 (Elite Edition)")
        version_label.setStyleSheet("color: #555; font-size: 11px; margin-bottom: 20px;")
        version_label.setAlignment(QtCore.Qt.AlignCenter)
        sidebar_layout.addWidget(version_label)

        # Badge Row Section
        badge_container = QtWidgets.QWidget()
        badge_row = QtWidgets.QHBoxLayout(badge_container)
        badge_row.setContentsMargins(0, 0, 0, 15)
        badge_row.setSpacing(5)

        def create_badge_label(text, color="#00b0ff"):
            lbl = QtWidgets.QLabel(text.upper())
            lbl.setAlignment(QtCore.Qt.AlignCenter)
            lbl.setStyleSheet(f"background-color: {color}; color: #08121a; font-weight: bold; font-size: 8px; border-radius: 2px; padding: 2px 4px;")
            return lbl

        badge_row.addWidget(create_badge_label("Python 3.8+"))
        badge_row.addWidget(create_badge_label("Asyncio", "#00e676"))
        badge_row.addWidget(create_badge_label("Phantom Blue"))
        
        license_btn = QtWidgets.QPushButton("MIT")
        license_btn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        license_btn.setStyleSheet("""
            QPushButton {
                background-color: #00b0ff;
                color: #08121a;
                font-weight: bold;
                font-size: 8px;
                border-radius: 2px;
                padding: 1px 4px;
                border: none;
            }
            QPushButton:hover {
                background-color: #00e676;
            }
        """)
        license_btn.clicked.connect(self.show_license)
        badge_row.addWidget(license_btn)

        sidebar_layout.addWidget(badge_container)

        sidebar_layout.addWidget(QtWidgets.QLabel("<b>Target Configuration</b>"))
        self.target_input = QtWidgets.QLineEdit()
        self.target_input.setPlaceholderText("example.com")
        sidebar_layout.addWidget(self.target_input)

        sidebar_layout.addWidget(QtWidgets.QLabel("Threads (Concurrency)"))
        self.thread_spin = QtWidgets.QSpinBox()
        self.thread_spin.setRange(1, 100)
        self.thread_spin.setValue(30)
        sidebar_layout.addWidget(self.thread_spin)

        sidebar_layout.addWidget(QtWidgets.QLabel("Custom Rules (YAML)"))
        self.rules_path = QtWidgets.QLineEdit()
        btn_rules = QtWidgets.QPushButton("Browse")
        btn_rules.clicked.connect(lambda: self.browse_file(self.rules_path, "YAML files (*.yml *.yaml)"))
        rb_layout = QtWidgets.QHBoxLayout()
        rb_layout.addWidget(self.rules_path)
        rb_layout.addWidget(btn_rules)
        sidebar_layout.addLayout(rb_layout)

        sidebar_layout.addWidget(QtWidgets.QLabel("User-Agents (TXT)"))
        self.ua_path = QtWidgets.QLineEdit()
        btn_ua = QtWidgets.QPushButton("Browse")
        btn_ua.clicked.connect(lambda: self.browse_file(self.ua_path, "Text files (*.txt)"))
        ua_layout = QtWidgets.QHBoxLayout()
        ua_layout.addWidget(self.ua_path)
        ua_layout.addWidget(btn_ua)
        sidebar_layout.addLayout(ua_layout)

        self.pentest_cb = QtWidgets.QCheckBox("Enable Pentest Mode (Orchestration)")
        sidebar_layout.addWidget(self.pentest_cb)

        self.start_btn = QtWidgets.QPushButton("🚀 START SCAN")
        self.start_btn.setFixedHeight(50)
        self.start_btn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #00b0ff;
                color: #081a12;
                font-weight: bold;
                font-size: 14px;
                border-radius: 4px;
                border: 1px solid #00e676;
            }
            QPushButton:hover {
                background-color: #00e676;
            }
            QPushButton:pressed {
                background-color: #00893b;
            }
        """)
        self.start_btn.clicked.connect(self.start_scan)
        sidebar_layout.addWidget(self.start_btn)

        # Progress Bar
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #2a2a2a;
                border-radius: 4px;
                text-align: center;
                background-color: #121212;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #00b0ff;
                width: 20px;
            }
        """)
        self.progress_bar.setVisible(False)
        sidebar_layout.addWidget(self.progress_bar)

        sidebar_layout.addStretch()

        # --- Developer Info ---
        dev_info = QtWidgets.QFrame()
        dev_info.setFrameShape(QtWidgets.QFrame.StyledPanel)
        dev_info.setStyleSheet("background-color: #1e1e1e; border-radius: 5px; padding: 10px;")
        dev_layout = QtWidgets.QVBoxLayout(dev_info)
        
        dev_label = QtWidgets.QLabel("<b>👨‍💻 Developer - Alinshan</b>")
        dev_label.setStyleSheet("color: #00b0ff; font-size: 13px;")
        dev_layout.addWidget(dev_label)

        gh_label = QtWidgets.QLabel('<a href="https://github.com/Alinshan/tracehop" style="color: #7f8c8d; text-decoration: none;">🔗 GitHub - Tracehop</a>')
        gh_label.setOpenExternalLinks(True)
        gh_label.setStyleSheet("font-size: 12px;")
        dev_layout.addWidget(gh_label)

        copyright_label = QtWidgets.QLabel("© Alinshan 2026")
        copyright_label.setStyleSheet("color: #555; font-size: 10px; margin-top: 5px;")
        copyright_label.setAlignment(QtCore.Qt.AlignCenter)
        dev_layout.addWidget(copyright_label)

        sidebar_layout.addWidget(dev_info)
        layout.addWidget(sidebar)

        # Main Content Area
        content_layout = QtWidgets.QVBoxLayout()
        content_layout.setContentsMargins(10, 0, 10, 10)
        
        # Tabs for Results and Logs
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #2a2a2a; background: #121212; }
            QTabBar::tab { background: #1e1e1e; color: #777; padding: 12px 25px; border: 1px solid #2a2a2a; border-bottom: none; margin-right: 2px; }
            QTabBar::tab:selected { background: #121212; color: #00b0ff; border-top: 3px solid #00b0ff; }
        """)
        content_layout.addWidget(self.tabs)

        # Results Tab
        results_widget = QtWidgets.QWidget()
        self.res_layout = QtWidgets.QVBoxLayout(results_widget)
        self.table = QtWidgets.QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Rule Found", "Source URL", "Context"])
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setStyleSheet("""
            QTableWidget { background-color: #121212; color: #e0e0e0; font-family: 'Consolas', 'Segoe UI'; gridline-color: transparent; border: none; outline: none; }
            QTableWidget::item { padding: 12px; border-bottom: 1px solid #1a1a1a; }
            QHeaderView::section { background-color: #1a1a1a; color: #00b0ff; padding: 12px; font-weight: bold; border: none; border-bottom: 2px solid #00b0ff; }
        """)
        self.res_layout.addWidget(self.table)
        self.tabs.addTab(results_widget, "🎯 Findings")

        # --- Tab 2: Technical Intelligence (New) ---
        recon_widget = QtWidgets.QWidget()
        self.recon_layout = QtWidgets.QVBoxLayout(recon_widget)
        self.recon_tree = QtWidgets.QTreeWidget()
        self.recon_tree.setHeaderLabels(["Category", "Details"])
        self.recon_tree.setColumnWidth(0, 200)
        self.recon_tree.setStyleSheet("""
            QTreeWidget { background-color: #121212; color: #e0e0e0; font-family: 'Consolas', 'Segoe UI'; border: none; }
            QHeaderView::section { background-color: #1a1a1a; color: #00b0ff; padding: 10px; font-weight: bold; border-bottom: 2px solid #00b0ff; }
        """)
        self.recon_layout.addWidget(self.recon_tree)
        self.tabs.addTab(recon_widget, "🔍 Intelligence")

        # Log Tab
        log_container = QtWidgets.QWidget()
        log_cont_layout = QtWidgets.QVBoxLayout(log_container)
        log_cont_layout.setContentsMargins(0, 0, 0, 0)
        
        # Large Background ASCII Cat (Custom Generated)
        large_cat = r"""
                      .*=:       :*-                        
                      -@@@*=++=-+@@*                        
                      -@@@@@@@@@@@@*                        
                      *@@@@@@@@@@@@@#-                      
                     *@@@@@@@@@%+=:::++                     
                    =@@@@@@@@#-       #.                    
                    #@@@@@@@+    :.   #.                    
                   .%@@@@@@=  ..*@@-..#                     
                    #@@@@@# -**%@%+@+.+.                    
                    =@@@@@=.**+*%@#@--=-                    
                     +@@@@* =*%@@@%--*..                    
                      +%@@@= .-==-.=*.                      
                      .+@@@@*.   :*=                        
                        .=*@@@= -#:                         
                           .-##=*=                          
                              :-=:                          
        """
        self.log_output = WatermarkPlainTextEdit(large_cat)
        self.log_output.setReadOnly(True)
        
        # Ensure the container has the dark background since the edit is transparent
        log_container.setStyleSheet("background-color: #1a1a1a;")
        log_cont_layout.addWidget(self.log_output)
        
        self.tabs.addTab(log_container, "📜 Engine Logs")

        layout.addLayout(content_layout)

    def apply_dark_theme(self):
        palette = QtGui.QPalette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(45, 45, 45))
        palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Base, QtGui.QColor(30, 30, 30))
        palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(45, 45, 45))
        palette.setColor(QtGui.QPalette.ToolTipBase, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.ToolTipText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53, 53, 53))
        palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.BrightText, QtCore.Qt.red)
        palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(0, 200, 83))
        palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
        self.setPalette(palette)

    def browse_file(self, line_edit, filter):
        file, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File", "", filter)
        if file:
            line_edit.setText(file)

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_output.appendPlainText(f"[{timestamp}] {message}")

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QtWidgets.QMessageBox.warning(self, "Error", "Target domain is required.")
            return

        self.start_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0) # Indeterminate mode
        self.table.setRowCount(0)
        self.log_output.clear()
        self.tabs.setCurrentIndex(1) # Switch to logs

        self.thread = QtCore.QThread()
        self.worker = ScanWorker(
            target, 
            self.thread_spin.value(),
            self.rules_path.text(),
            self.ua_path.text(),
            self.pentest_cb.isChecked()
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.progress.connect(self.log)
        self.thread.start()

    def on_scan_finished(self, results, recon_data, report_path):
        self.start_btn.setEnabled(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.thread.quit()
        self.thread.wait()
        
        self.log(f"Scan complete! Found {len(results)} secrets.")
        if recon_data:
            self.log("Technical Intelligence gathered (DNS, SSL, Tech).")

        if report_path:
            self.log(f"Pentest report generated: {report_path}")
            QtWidgets.QMessageBox.information(self, "Success", f"Pentest complete. Report at:\n{report_path}")

        # Update Findings Table
        self.tabs.setCurrentIndex(0) 
        self.table.setRowCount(len(results))
        for i, res in enumerate(results):
            self.table.setItem(i, 1, QtWidgets.QTableWidgetItem(res['rule']))
            self.table.setItem(i, 2, QtWidgets.QTableWidgetItem(res['source']))
            self.table.setItem(i, 3, QtWidgets.QTableWidgetItem(res['context']))
            sev = "MEDIUM"
            if any(x in res['rule'].lower() for x in ['key', 'secret', 'token', 'private']):
               sev = "HIGH"
            self.table.setItem(i, 0, QtWidgets.QTableWidgetItem(sev))

        # Update Intelligence Tree
        self.recon_tree.clear()
        if recon_data:
            # DNS
            if recon_data.get("dns"):
                dns_root = QtWidgets.QTreeWidgetItem(self.recon_tree, ["DNS Records", ""])
                for rtype, vals in recon_data["dns"].items():
                    QtWidgets.QTreeWidgetItem(dns_root, [rtype, ", ".join(vals)])
                dns_root.setExpanded(True)

            # SSL
            if recon_data.get("ssl"):
                ssl_root = QtWidgets.QTreeWidgetItem(self.recon_tree, ["SSL Certificate", ""])
                for k, v in recon_data["ssl"].items():
                    QtWidgets.QTreeWidgetItem(ssl_root, [k.capitalize(), str(v)])
                ssl_root.setExpanded(True)

            # Tech
            if recon_data.get("tech_stack"):
                tech_root = QtWidgets.QTreeWidgetItem(self.recon_tree, ["Technology Stack", ""])
                for tech in recon_data["tech_stack"]:
                    QtWidgets.QTreeWidgetItem(tech_root, ["Tech", tech])
                tech_root.setExpanded(True)

            # GeoIP
            if recon_data.get("geoip"):
                geo = recon_data["geoip"]
                geo_root = QtWidgets.QTreeWidgetItem(self.recon_tree, ["Geo-Location", ""])
                QtWidgets.QTreeWidgetItem(geo_root, ["IP Address", geo.get("ip")])
                QtWidgets.QTreeWidgetItem(geo_root, ["Location", f"{geo.get('city')}, {geo.get('country')}"])
                QtWidgets.QTreeWidgetItem(geo_root, ["ISP", geo.get("isp")])
                QtWidgets.QTreeWidgetItem(geo_root, ["AS", geo.get("as")])
                geo_root.setExpanded(True)

            # Ports
            if recon_data.get("ports"):
                ports_root = QtWidgets.QTreeWidgetItem(self.recon_tree, ["Open Ports", ""])
                QtWidgets.QTreeWidgetItem(ports_root, ["Ports", ", ".join(map(str, recon_data["ports"]))])
                ports_root.setExpanded(True)

    def show_license(self):
        license_path = os.path.join(os.getcwd(), "LICENSE")
        if os.path.exists(license_path):
            QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(license_path))
        else:
            QtWidgets.QMessageBox.information(self, "License", "MIT License (c) 2026 Alinshan")

def run_gui():
    app = QtWidgets.QApplication(sys.argv)
    window = TracehopGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    run_gui()
