import pyshark
from collections import defaultdict

# Liste des fichiers à analyser
pcap_files = [
    'all_captures/4G_captures.pcapng',
    'all_captures/4G_planA3.pcapng',
    'all_captures/capture_ilyasseetthoma_sender.pcapng',
    'all_captures/capture_ilyassethomas_4G.pcapng',
    'all_captures/captures.pcapng',
    'all_captures/Connexion_solo_WIFI.pcapng',
    'all_captures/dualwifi_captures.pcapng',
    'all_captures/ethernet_captures.pcapng',
    'all_captures/ethernet_planA3.pcapng',
    'all_captures/thomas_wifi_planA3.pcapng'
]

udp_packets = defaultdict(int)
quic_packets = defaultdict(int)

for pcap_file in pcap_files:
    print(f"\nAnalyse du fichier : {pcap_file}")
    capture = pyshark.FileCapture(pcap_file, display_filter='udp or quic')

    for pkt in capture:
        try:
            if hasattr(pkt, 'udp'):
                key = (pkt.ip.src, pkt.udp.srcport, pkt.ip.dst, pkt.udp.dstport, pkt.udp.length)
                udp_packets[key] += 1

            if hasattr(pkt, 'quic'):
                key = (pkt.ip.src, pkt.udp.srcport, pkt.ip.dst, pkt.udp.dstport, pkt.quic.packet_number)
                quic_packets[key] += 1
        except AttributeError:
            pass

    capture.close()

# Compter les doublons
udp_duplicates = sum(count - 1 for count in udp_packets.values() if count > 1)
quic_duplicates = sum(count - 1 for count in quic_packets.values() if count > 1)

# Affichage des résultats
print(f"\nNombre total de doublons UDP détectés : {udp_duplicates}")
print(f"Nombre total de doublons QUIC détectés : {quic_duplicates}")
