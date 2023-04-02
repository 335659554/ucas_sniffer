import tkinter as tk
from tkinter import ttk
import pyshark
from threading import Thread
import re
import socket
import os
import subprocess
import tempfile
import sys
import pcapy
import dpkt
from datetime import datetime
from scapy.all import PcapWriter, raw
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6



Tshark_path = "E:\\Wireshark\\tshark.exe" # 配置Tshark路径



def packet_matches_filter(packet, filter_text):
    if not filter_text:
        return True

    # 创建一个临时 pcap 文件
    temp_fd, temp_filename = tempfile.mkstemp(suffix='.pcap')
    os.close(temp_fd)

    # 将数据包保存为临时文件
    try:
        pkt = Ether(packet.get_raw_packet())
        if pkt.haslayer(IP):
            pkt = pkt[IP]
        elif pkt.haslayer(IPv6):
            pkt = pkt[IPv6]
        wrpcap(temp_filename, pkt)
    except Exception as e:
        print(f"Error while saving packet: {str(e)}")
        return False

    # 使用 tshark 运行过滤器
    tshark_command = f"tshark -r {temp_filename} -Y \"{filter_text}\""
    try:
        result = subprocess.run(tshark_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark command: {str(e)}")
        return False

    # 删除临时文件
    os.remove(temp_filename)

    # 检查数据包是否与过滤器匹配
    if result.returncode == 0 and result.stdout:
        return True
    else:
        return False


class SnifferApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Sniffer")
        self.create_widgets()
        self.packets = []
        self.stop_capture_flag = False  # 添加此行

    def create_widgets(self):
        self.interface_var = tk.StringVar()
        self.filter_var = tk.StringVar()

        top_frame = ttk.Frame(self.master)
        top_frame.pack(side=tk.TOP, fill=tk.X)
        middle_frame = ttk.Frame(self.master)
        middle_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        bottom_frame = ttk.Frame(self.master)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        # Interface selection
        interface_label = ttk.Label(top_frame, text="Interface:")
        interface_label.pack(side=tk.LEFT, padx=(0, 5))
        interface_entry = ttk.Entry(top_frame, textvariable=self.interface_var)
        interface_entry.pack(side=tk.LEFT, padx=(0, 10))

        # Filter
        filter_label = ttk.Label(top_frame, text="Filter:")
        filter_label.pack(side=tk.LEFT, padx=(0, 5))
        filter_entry = ttk.Entry(top_frame, textvariable=self.filter_var)
        filter_entry.pack(side=tk.LEFT, padx=(0, 10))

        # Buttons
        start_button = ttk.Button(top_frame, text="Start", command=self.start_sniffer)
        start_button.pack(side=tk.LEFT, padx=(0, 5))
        stop_button = ttk.Button(top_frame, text="Stop", command=self.stop_sniffer)
        stop_button.pack(side=tk.LEFT)

        apply_filter_button = ttk.Button(top_frame, text="Apply Filter", command=self.apply_filter)
        apply_filter_button.pack(side=tk.LEFT, padx=(10, 0))

        # Packet list
        self.packet_list = ttk.Treeview(middle_frame)
        self.packet_list["columns"] = ("no", "time", "source", "destination", "protocol", "length", "info")
        self.packet_list.column("#0", width=0, stretch=tk.NO)
        self.packet_list.heading("no", text="No.")
        self.packet_list.column("no", anchor=tk.W)
        self.packet_list.heading("time", text="Time")
        self.packet_list.column("time", anchor=tk.W)
        self.packet_list.heading("source", text="Source")
        self.packet_list.column("source", anchor=tk.W)
        self.packet_list.heading("destination", text="Destination")
        self.packet_list.column("destination", anchor=tk.W)
        self.packet_list.heading("protocol", text="Protocol")
        self.packet_list.column("protocol", anchor=tk.W)
        self.packet_list.heading("length", text="Length")
        self.packet_list.column("length", anchor=tk.W)
        self.packet_list.heading("info", text="Info")
        self.packet_list.column("info", anchor=tk.W)

        self.packet_list.bind("<Double-1>", self.on_packet_double_click)
        self.packet_list.bind("<Button-3>", self.on_packet_right_click)  # 添加鼠标右键单击绑定
        self.packet_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(middle_frame, command=self.packet_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_list.configure(yscrollcommand=scrollbar.set)

        # Packet details
        details_frame = ttk.Frame(bottom_frame)
        details_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.packet_details = ttk.Treeview(details_frame)
        self.packet_details["columns"] = ("field", "value")
        self.packet_details.column("#0", width=0, stretch=tk.NO)
        self.packet_details.heading("field", text="Field")
        self.packet_details.column("field", anchor=tk.W)
        self.packet_details.heading("value", text="Value")
        self.packet_details.column("value", anchor=tk.W)
        self.packet_details.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Packet binary data
        binary_frame = ttk.Frame(bottom_frame)
        binary_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.binary_data = tk.Text(binary_frame, wrap=tk.NONE)
        self.binary_data.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        binary_scrollbar_x = ttk.Scrollbar(binary_frame, orient=tk.HORIZONTAL, command=self.binary_data.xview)
        binary_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        binary_scrollbar_y = ttk.Scrollbar(binary_frame, orient=tk.VERTICAL, command=self.binary_data.yview)
        binary_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.binary_data.configure(xscrollcommand=binary_scrollbar_x.set, yscrollcommand=binary_scrollbar_y.set)

    def start_sniffer(self):
        self.capture = pyshark.LiveCapture(
            interface=self.interface_var.get(),
            tshark_path=Tshark_path,
            use_json=True,
            include_raw=True
        )

        self.capture_thread = Thread(target=self.run_capture)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def run_capture(self):
        while not self.stop_capture_flag:
            try:
                self.capture.apply_on_packets(self.handle_packet, packet_count=1)
            except Exception as e:
                print(f"Error while capturing packet: {str(e)}")

    def handle_packet(self, pkt):
        self.packets.append(pkt)
        if self.filter_var.get() == "" or packet_matches_filter(pkt, self.filter_var.get()):
            self.display_packet(pkt)

    def stop_sniffer(self):
        self.stop_capture_flag = True  # 添加此行
        if hasattr(self, "capture"):
            self.capture.close()
        if hasattr(self, "capture_thread"):
            self.capture_thread.join()

    def apply_filter(self):
        filter_text = self.filter_var.get()
        self.packet_list.delete(*self.packet_list.get_children())

        for pkt in self.packets:
            if filter_text == "" or packet_matches_filter(pkt, filter_text):
                self.display_packet(pkt)



    def display_packet(self, pkt):
        protocol = pkt.transport_layer if hasattr(pkt, "transport_layer") else ""
        packet_info = ""

        if protocol == "TCP":
            packet_info = f"Seq={pkt.tcp.seq}, Ack={pkt.tcp.ack}, Win={pkt.tcp.window_size}"
        elif protocol == "UDP":
            packet_info = f"Src Port={pkt.udp.srcport}, Dst Port={pkt.udp.dstport}"
        elif protocol == "ICMP":
            packet_info = f"Type={pkt.icmp.type}, Code={pkt.icmp.code}"
        elif protocol == "HTTP":
            packet_info = f"Request Method={pkt.http.request_method}, URI={pkt.http.request_uri}"
        elif protocol == "ARP":
            packet_info = f"Opcode={pkt.arp.opcode}, Sender MAC={pkt.arp.src_hw_mac}, Sender IP={pkt.arp.src_proto_ipv4}, Target MAC={pkt.arp.dst_hw_mac}, Target IP={pkt.arp.dst_proto_ipv4}"
        # 可以添加更多协议类型的信息

        packet = {
            "no": len(self.packet_list.get_children()) + 1,
            "time": datetime.fromtimestamp(pkt.sniff_time.timestamp()).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "source": pkt.ip.src if hasattr(pkt, "ip") else "",
            "destination": pkt.ip.dst if hasattr(pkt, "ip") else "",
            "protocol": protocol,
            "length": pkt.length,
            "info": packet_info
        }

        if hasattr(pkt, "ipv6"):
            packet["source"] = pkt.ipv6.src
            packet["destination"] = pkt.ipv6.dst

        self.packet_list.insert("", tk.END, values=(
            packet["no"], packet["time"], packet["source"], packet["destination"], packet["protocol"], packet["length"],
            packet["info"]))

    def on_packet_double_click(self, event):
        selected_items = self.packet_list.selection()
        if len(selected_items) != 1:
            return
        item = selected_items[0]
        packet_no = self.packet_list.item(item, "values")[0]
        pkt = self.packets[int(packet_no) - 1]

        self.display_packet_details(pkt)
        self.display_binary_data(pkt)

    def display_packet_details(self, pkt):
        self.packet_details.delete(*self.packet_details.get_children())
        layers = [("frame", "frame_info"), ("eth", "eth"), ("ip", "ip"), ("tcp", "tcp"), ("udp", "udp"), ("http", "http"), ("dns", "dns"), ("arp", "arp")]

        for layer, layer_name in layers:
            if hasattr(pkt, layer):
                layer_item = self.packet_details.insert("", tk.END, text=layer_name, values=("",))
                layer_obj = getattr(pkt, layer)
                for field in layer_obj.field_names:
                    field_value = getattr(layer_obj, field)
                    self.packet_details.insert(layer_item, tk.END, text="", values=(field, field_value))

    def display_binary_data(self, pkt):
        self.binary_data.delete("1.0", tk.END)

        # 获取整个原始数据包的内容
        raw_data = raw(Ether(pkt.get_raw_packet()))
        formatted_data = " ".join("{:02X}".format(byte) for byte in raw_data)

        # 添加ASCII字符表示
        ascii_data = ""
        for byte in raw_data:
            if 32 <= byte <= 126:
                ascii_data += chr(byte)
            else:
                ascii_data += "."

        # 将ASCII字符表示添加到格式化的十六进制数据中
        formatted_data_with_ascii = ""
        for i in range(0, len(formatted_data), (3 * 16)):
            hex_chunk = formatted_data[i:i + (3 * 16)]
            ascii_chunk = ascii_data[int(i / 3):int(i / 3) + 16]
            formatted_data_with_ascii += hex_chunk + "  " + ascii_chunk + "\n"

        self.binary_data.insert(tk.END, formatted_data_with_ascii)

    def on_packet_right_click(self, event):
        item = self.packet_list.identify_row(event.y)
        if not item:
            return

        packet_no = self.packet_list.item(item, "values")[0]
        pkt = self.packets[int(packet_no) - 1]

        menu = tk.Menu(self.master, tearoff=0)
        menu.add_command(label="Send to Wireshark", command=lambda: self.send_to_wireshark(pkt))
        if hasattr(pkt, "tcp"):  # 添加新的菜单项以进行TCP流追踪
            menu.add_command(label="Trace TCP Stream", command=lambda: self.trace_tcp_stream(pkt))
        menu.post(event.x_root, event.y_root)

    def trace_tcp_stream(self, pkt):
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        src_port = pkt.tcp.srcport
        dst_port = pkt.tcp.dstport
        filter_expr = f"(ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.srcport == {src_port} && tcp.dstport == {dst_port}) || (ip.src == {dst_ip} && ip.dst == {src_ip} && tcp.srcport == {dst_port} && tcp.dstport == {src_port})"
        self.filter_var.set(filter_expr)
        self.apply_filter()

    def send_to_wireshark(self, pkt):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
            tmp_filename = f.name

            # Create a pcap file with Dpkt
            pcap = dpkt.pcap.Writer(f)
            ts = float(pkt.sniff_timestamp)
            sec = int(ts)
            usec = int((ts - sec) * 1000000)
            pcap.writepkt_time(pkt.get_raw_packet(), sec + (usec / 1000000))
            pcap.close()

            # Run Wireshark with the temporary pcap file
            if sys.platform.startswith("win"):
                subprocess.run(["wireshark", "-r", tmp_filename], shell=True)
            else:
                subprocess.run(["wireshark", "-r", tmp_filename])


def main():
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
