import sys
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, QMessageBox, QHeaderView
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt
from PyQt5.QtGui import QIcon
from scapy.all import sniff, IP, IPv6

class PacketCaptureThread(QThread):
    packet_received = pyqtSignal(object)
    pause_flag = False

    def __init__(self, packet_filter):
        super(PacketCaptureThread, self).__init__()
        self.packet_filter = packet_filter

    def run(self):
        sniff(prn=lambda packet: self.packet_received.emit(packet),
              store=0, stop_filter=lambda x: not self.isRunning() or self.pause_flag)

    def pause(self):
        self.pause_flag = True

    def resume(self):
        self.pause_flag = False

class SimplePacketAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Simple Packet Analyzer")
        self.setGeometry(0, 0, 800, 600)

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        self.table = QTableWidget(self)
        self.table.setStyleSheet("background-color: lightgreen;")  # Set background color
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Serial Number", "Source", "Destination", "Header", "Network Type"])

        self.table.setColumnWidth(0, 150)  # Serial Number
        self.table.setColumnWidth(1, 200)  # Source
        self.table.setColumnWidth(2, 200)  # Destination
        self.table.setColumnWidth(3, 100)  # Header
        self.table.setColumnWidth(4, 150)  # Network Type

        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # Stretch columns to fit width

        main_layout.addWidget(self.table)

        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter Expression:")
        self.filter_entry = QLineEdit()
        apply_filter_button = QPushButton("Apply Filter")
        apply_filter_button.clicked.connect(self.apply_filter)
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_entry)
        filter_layout.addWidget(apply_filter_button)
        main_layout.addLayout(filter_layout)

        header_filter_layout = QHBoxLayout()
        header_filter_label = QLabel("Header Filter:")
        self.header_filter_entry = QLineEdit()
        header_filter_layout.addWidget(header_filter_label)
        header_filter_layout.addWidget(self.header_filter_entry)
        main_layout.addLayout(header_filter_layout)

        button_layout = QHBoxLayout()
        start_button = QPushButton("Start Capture")
        pause_button = QPushButton("Pause Capture")
        resume_button = QPushButton("Resume Capture")
        reset_button = QPushButton("Reset Capture")
        clear_button = QPushButton("Clear Packets")

        button_layout.addWidget(start_button)
        button_layout.addWidget(pause_button)
        button_layout.addWidget(resume_button)
        button_layout.addWidget(reset_button)
        button_layout.addWidget(clear_button)

        main_layout.addLayout(button_layout)

        self.status_label = QLabel("Total Packets: 0 | Time Elapsed: 0s")
        main_layout.addWidget(self.status_label)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status_label)

        self.packet_capture_thread = PacketCaptureThread("")
        self.packet_capture_thread.packet_received.connect(self.packet_callback)

        start_button.clicked.connect(self.start_capture)
        pause_button.clicked.connect(self.pause_capture)
        resume_button.clicked.connect(self.resume_capture)
        reset_button.clicked.connect(self.reset_capture)
        clear_button.clicked.connect(self.clear_packets)

        self.capture_state = False

        # Connect double-click event to method
        self.table.itemDoubleClicked.connect(self.show_packet_details)

        # Set window to full screen
        self.showFullScreen()

    def start_capture(self):
        if not self.packet_capture_thread.isRunning():
            self.table.setRowCount(0)  # Clear existing rows
            self.packet_count = 0
            self.start_time = time.time()  # Set start_time to current time

            filter_expression = self.filter_entry.text()
            header_filter = self.header_filter_entry.text()

            if header_filter:
                filter_expression += f" and {header_filter}"

            self.packet_capture_thread.packet_filter = filter_expression
            self.packet_capture_thread.start()

            self.capture_state = True
            self.timer.start(1000)

    def apply_filter(self):
        self.pause_capture()
        self.start_capture()

    def packet_callback(self, packet):
        try:
            if IP in packet:
                source = packet[IP].src
                destination = packet[IP].dst
                header = "IP"
                network_type = "IPv4"
            elif IPv6 in packet:
                source = packet[IPv6].src
                destination = packet[IPv6].dst
                header = "IPv6"
                network_type = "IPv6"
            else:
                source = destination = header = network_type = "N/A"

            self.packet_count += 1
            formatted_source = self.format_dynamic(source, header)
            formatted_destination = self.format_dynamic(destination, header)

            # Add a row to the table for each received packet
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            self.table.setItem(row_position, 0, QTableWidgetItem(str(self.packet_count)))
            self.table.setItem(row_position, 1, QTableWidgetItem(formatted_source))
            self.table.setItem(row_position, 2, QTableWidgetItem(formatted_destination))
            self.table.setItem(row_position, 3, QTableWidgetItem(header))
            self.table.setItem(row_position, 4, QTableWidgetItem(network_type))
        except Exception as e:
            print(f"Error processing packet: {e}")

    def format_dynamic(self, value, header):
        if header == "IP":
            return f"{value}"
        elif header == "IPv6":
            return f"{value}"       
        else:
            return value

    def pause_capture(self):
        self.packet_capture_thread.pause()
        self.capture_state = False
        self.timer.stop()

    def resume_capture(self):
        if not self.packet_capture_thread.isRunning():
            self.packet_capture_thread.resume()
            self.capture_state = True
            self.timer.start()

    def reset_capture(self):
        self.pause_capture()
        self.clear_packets()
        self.start_time = 0  # Reset start_time to 0

    def clear_packets(self):
        self.table.setRowCount(0)
        self.packet_count = 0
        self.start_time = time.time()  # Reset start_time to current time
        self.update_status_label()

    def update_status_label(self):
        elapsed_time = round(time.time() - self.start_time, 2)
        self.status_label.setText(f"Total Packets: {self.packet_count} | Time Elapsed: {elapsed_time}s")

    def show_packet_details(self, item):
        # Retrieve row and column of the double-clicked item
        row = item.row()
        column = item.column()

        # Retrieve packet details from the selected row
        serial_number = self.table.item(row, 0).text()
        source = self.table.item(row, 1).text()
        destination = self.table.item(row, 2).text()
        header = self.table.item(row, 3).text()
        network_type = self.table.item(row, 4).text()

        # Create a message box to display packet details
        message = f"Serial Number: {serial_number}\nSource: {source}\nDestination: {destination}\nHeader: {header}\nNetwork Type: {network_type}"
        QMessageBox.information(self, "Packet Details", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = SimplePacketAnalyzer()
    main_window.show()
    sys.exit(app.exec_())
