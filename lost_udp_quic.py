import pyshark
from collections import defaultdict

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

# Dictionnaire pour regrouper les flux QUIC sur tous les fichiers
quic_flows = defaultdict(list)

# Parcours de chaque fichier de capture
for pcap_file in pcap_files:
    print(f"\nAnalyse du fichier : {pcap_file}")
    capture = pyshark.FileCapture(pcap_file, display_filter='quic', keep_packets=False)
    
    for pkt in capture:
        try:
            # Construction d'une clé de flux avec IP source, IP destination et l'ID de connexion QUIC (si présent)
            src = pkt.ip.src
            dst = pkt.ip.dst
            conn_id = pkt.quic.connection_id if hasattr(pkt.quic, 'connection_id') else "no_id"
            flow_key = (src, dst, conn_id)
            
            # Extraction et conversion du numéro de paquet QUIC
            packet_num = int(pkt.quic.packet_number)
            quic_flows[flow_key].append(packet_num)
        except AttributeError:
            # Passage au paquet suivant en cas de champ manquant
            continue

    capture.close()

# Analyse de la continuité des numéros de paquet pour chaque flux QUIC
for flow, numbers in quic_flows.items():
    numbers.sort()
    missing_ranges = []
    prev = numbers[0]
    for num in numbers[1:]:
        if num != prev + 1:
            missing_ranges.append((prev + 1, num - 1))
        prev = num
    if missing_ranges:
        print(f"Flux {flow} présente des gaps dans la numérotation : {missing_ranges}")
    else:
        print(f"Flux {flow} : aucune anomalie dans la numérotation détectée.")
