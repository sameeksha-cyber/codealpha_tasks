from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

LOG_FILE = "logs.txt"


def log_alert(message):
    with open(LOG_FILE, "a") as file:
        file.write(f"{datetime.now()} : {message}\n")


def packet_callback(packet):

    if IP in packet:

        src = packet[IP].src
        dst = packet[IP].dst

        print("\n" + "=" * 60)
        print("      NETWORK INTRUSION DETECTION SYSTEM")
        print("=" * 60)
        print(f"Source IP       : {src}")
        print(f"Destination IP  : {dst}")

        if TCP in packet:

            sport = packet[TCP].sport
            dport = packet[TCP].dport

            print("Protocol        : TCP")
            print(f"Source Port     : {sport}")
            print(f"Destination Port: {dport}")

            if dport == 80:
                print("[INFO] HTTP Traffic Detected")

            elif dport == 443:
                print("[INFO] HTTPS Traffic Detected")

            elif dport == 22:
                print("[ALERT] SSH Traffic Detected")

            log_alert(
                f"TCP | {src}:{sport} -> {dst}:{dport}"
            )

        elif UDP in packet:

            sport = packet[UDP].sport
            dport = packet[UDP].dport

            print("Protocol        : UDP")
            print(f"Source Port     : {sport}")
            print(f"Destination Port: {dport}")

            log_alert(
                f"UDP | {src}:{sport} -> {dst}:{dport}"
            )

        elif ICMP in packet:

            print("Protocol        : ICMP")
            print("[ALERT] Ping Packet Detected")

            log_alert(
                f"ICMP | {src} -> {dst}"
            )

        print("=" * 60)


print("=" * 60)
print("   NETWORK INTRUSION DETECTION SYSTEM STARTED")
print("=" * 60)
print("Monitoring network traffic...")
print("Press CTRL + C to stop.\n")

sniff(prn=packet_callback, store=False)