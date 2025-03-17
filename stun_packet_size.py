import pyshark
import numpy as np

# Liste des fichiers de capture à analyser
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

def average_stun_packet_size(pcap_list):
    """
    Parcourt une liste de fichiers pcap, filtre les paquets STUN,
    enregistre leurs tailles et calcule la taille moyenne.
    """
    stun_sizes = []

    for pcap_file in pcap_list:
        print(f"Analyse du fichier : {pcap_file}")
        capture = pyshark.FileCapture(pcap_file, display_filter='stun', keep_packets=False)

        for pkt in capture:
            try:
                pkt_length = int(pkt.length)
                stun_sizes.append(pkt_length)
            except AttributeError:
                # Certains paquets peuvent ne pas avoir le champ length
                pass

        capture.close()

    if stun_sizes:
        return np.mean(stun_sizes)
    else:
        return 0

average_size = average_stun_packet_size(pcap_files)
print(f"\nTaille moyenne des paquets STUN : {average_size:.2f} octets")
