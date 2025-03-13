import pyshark

# Liste des fichiers pcapng à analyser
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

# Parcourir chaque fichier de capture
for pcap_file in pcap_files:
    print(f"\nAnalyse du fichier : {pcap_file}")
    cap = pyshark.FileCapture(pcap_file, display_filter='esp or ah or isakmp or udp.port==500 or udp.port==4500 or ipvs')

    for pkt in cap:
        protocol = pkt.highest_layer
        src = pkt.ip.src
        dst = pkt.ip.dst

        if protocol == 'ESP':
            print(f"[ESP] {src} --> {dst}")
        elif protocol == 'AH':
            print(f"[AH] {src} --> {dst}")
        elif protocol == 'ISAKMP' or (protocol == 'UDP' and (pkt.udp.srcport in ['500', '4500'] or pkt.udp.dstport in ['500', '4500'])):
            src_port = pkt.udp.srcport
            dst_port = pkt.udp.dstport
            print(f"[ISAKMP/IKE] {src}:{src_port} --> {dst}:{dst_port}")

    cap.close()
