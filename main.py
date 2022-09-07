from scapy.all import AsyncSniffer

import time
import os

# 给实验室网关上使用的流量日志审计工具

iface_list = ["eth0"] # 监听的网卡
capture_period = 86400 # 日志记录周期
log_file_name = "packets.log" # 日志位置
keep_number = 90 # 保留天数

cl = None

class CapturedPacket(object):
    def __init__(self):
        self.eth_src = None
        self.eth_dst = None

        self.ip_proto = None
        self.ip_src = None
        self.ip_dst = None
        
        self.t_proto = None
        self.src_port = None
        self.dst_port = None

        self.icmp_proto = None
        self.icmp_type = None
        self.icmp_code = None

        self.arp_op = None
        self.arp_hwsrc = None
        self.arp_hwdst = None
        self.arp_psrc = None
        self.arp_pdst = None

    def __repr__(self):
        msg = ""
        if self.eth_src and self.eth_dst:
            msg += f"Ether [src:{self.eth_src} dst:{self.eth_dst}] "

        if self.t_proto and self.ip_proto:
            msg += f"{self.ip_proto}:{self.t_proto} [{self.ip_src}:{self.src_port} > {self.ip_dst}:{self.dst_port}] "
        elif self.icmp_proto and self.ip_proto:
            msg += f"{self.ip_proto}:{self.icmp_proto} [{self.ip_src} > {self.ip_dst} type:{self.icmp_type} code:{self.icmp_code}] "
        elif self.ip_proto:
            msg += f"{self.ip_proto} [src:{self.ip_src} dst:{self.ip_dst}] "

        if self.arp_op:
            msg += f"ARP [op: {self.arp_op} hwsrc:{self.arp_hwsrc} hwdst:{self.arp_hwdst} psrc:{self.arp_psrc} pdst:{self.arp_pdst}]"
        msg += "\n"
        return msg


class CapturedLogger(object):
    def __init__(self, log_file_name: str = log_file_name):
        self.storage = {}
        self.log_file_name = log_file_name
        self.f = open(self.log_file_name,'a')

    def __del__(self):
        self.f.close()

    def get_hash_key(self, cp: CapturedPacket):
        key = "default"
        if cp.ip_proto and cp.t_proto:
            key = f"{cp.t_proto}:{cp.ip_src}:{cp.ip_dst}:{cp.dst_port}"
        elif cp.ip_proto:
            key = f"{cp.ip_proto}:{cp.ip_src}:{cp.ip_dst}"
        elif cp.arp_op is not None:
            key = f"{cp.arp_op}:{cp.arp_hwsrc}:{cp.arp_hwdst}:{cp.arp_psrc}:{cp.arp_pdst}"
        else:
            key = f"Ether:{cp.eth_src}:{cp.eth_dst}"
        return key

    def isUnique(self, cp: CapturedPacket):
        key = self.get_hash_key(cp)
        return not key in self.storage

    def log_rotate(self):

        if self.f:
            self.f.close()
        try:
            today_time = time.strftime("%Y-%m-%d-%H:%M:%S", time.localtime())
            os.rename(self.log_file_name, f"{self.log_file_name}-{today_time}")
        except:
            pass

        workspace_path, prefix_file_name = os.path.split(self.log_file_name)
        if workspace_path == "":
            workspace_path = os.getcwd()

        log_all_files_list = os.listdir(workspace_path)
        log_files_list = [file for file in log_all_files_list if prefix_file_name in file]
        log_files_list.sort(key=lambda file: os.path.getmtime(os.path.join(workspace_path, file)))

        if len(log_files_list) >= keep_number:
            remove_files_list = log_files_list[:-keep_number]

            for file in remove_files_list:
                print(f"delete file: {os.path.join(workspace_path, file)}")
                os.remove(os.path.join(workspace_path, file))
        
        self.f = open(self.log_file_name,'a')
        self.storage.clear()

    def handle(self, cp: CapturedPacket):
        if not self.isUnique(cp):
            return
        
        key = self.get_hash_key(cp)
        self.storage[key] = cp
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.f.write(f"{current_time} {cp}")
        self.f.flush()

def prn_monitor_callback(pkt):
    cp = CapturedPacket()

    if "Ether" in pkt:
        cp.eth_src = pkt["Ether"].src
        cp.eth_dst = pkt["Ether"].dst

    if "IP" in pkt:
        cp.ip_proto = "IPv4"
        cp.ip_src = pkt["IP"].src
        cp.ip_dst = pkt["IP"].dst

    if "IPv6" in pkt:
        cp.ip_proto = "IPv6"
        cp.ip_src = pkt["IPv6"].src
        cp.ip_dst = pkt["IPv6"].dst

    if "TCP" in pkt:
        cp.t_proto = "TCP"
        cp.src_port = pkt["TCP"].sport
        cp.dst_port = pkt["TCP"].dport

    if "UDP" in pkt:
        cp.t_proto = "UDP"
        cp.src_port = pkt["UDP"].sport
        cp.dst_port = pkt["UDP"].dport
    
    if "ICMP" in pkt:
        cp.icmp_proto = "ICMP"
        cp.icmp_type = pkt["ICMP"].type
        cp.icmp_code = pkt["ICMP"].code

    if "ICMPv6" in pkt:
        cp.icmp_proto = "ICMPv6"
        cp.icmp_type = pkt["ICMPv6"].type
        cp.icmp_code = pkt["ICMPv6"].code
    
    if "ARP" in pkt:
        cp.arp_op = pkt["ARP"].op
        cp.arp_hwsrc = pkt["ARP"].hwsrc
        cp.arp_hwdst = pkt["ARP"].hwdst
        cp.arp_psrc = pkt["ARP"].psrc
        cp.arp_pdst = pkt["ARP"].pdst

    global cl
    if cl is not None:
        cl.handle(cp)
    return str(cp)


def main():
    global cl
    cl = CapturedLogger(log_file_name)

    capture = AsyncSniffer(iface=iface_list, prn=prn_monitor_callback, store=False)
    while True:
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        print(f"start new period: {current_time}")
        capture.start()
        time.sleep(capture_period)
        if cl is not None:
            cl.log_rotate()
        capture.stop()

if __name__ == "__main__":
    main()