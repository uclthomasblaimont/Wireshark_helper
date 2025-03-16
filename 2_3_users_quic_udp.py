import pyshark
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

# Définition des fichiers de capture
pcap_files = {
    "3 users": 'all_captures/thomas_wifi_planA3.pcapng',
    "2 users": 'all_captures/dualwifi_captures.pcapng'
}

# Dictionnaires pour stocker les tailles des paquets
size_data = {
    "3 users": {"udp": [], "quic": []},
    "2 users": {"udp": [], "quic": []}
}

# Dictionnaires pour stocker les données de pertes et doublons pour QUIC
loss_data = {
    "3 users": {"duplicates": 0, "losses": 0},
    "2 users": {"duplicates": 0, "losses": 0}
}

# Pour chaque capture, on traite les paquets UDP et QUIC
for label, filename in pcap_files.items():
    print(f"\nAnalyse du fichier : {filename} ({label})")
    capture = pyshark.FileCapture(filename, display_filter="udp or quic", keep_packets=False)

    # Pour détecter les doublons et pertes dans QUIC, on regroupe les paquets par flux
    quic_flows = defaultdict(list)

    for pkt in capture:
        try:
            # Si le paquet contient UDP, on enregistre sa taille
            if hasattr(pkt, 'udp'):
                size = int(pkt.length)
                size_data[label]["udp"].append(size)

            # Pour les paquets QUIC, on enregistre également la taille et on regroupe par flux
            if hasattr(pkt, 'quic'):
                size = int(pkt.length)
                size_data[label]["quic"].append(size)

                # Construction d'une clé de flux basée sur IP source, IP destination et Connection ID (s'il existe)
                src = pkt.ip.src
                dst = pkt.ip.dst
                conn_id = pkt.quic.connection_id if hasattr(pkt.quic, 'connection_id') else "no_id"
                flow_key = (src, dst, conn_id)
                packet_num = int(pkt.quic.packet_number)
                quic_flows[flow_key].append(packet_num)
        except Exception as e:
            continue
    capture.close()

    # Analyse des flux QUIC pour compter les doublons et les pertes
    duplicates = 0
    losses = 0
    for flow, numbers in quic_flows.items():
        numbers.sort()
        prev = numbers[0]
        for num in numbers[1:]:
            if num == prev:
                duplicates += 1
            elif num > prev + 1:
                losses += (num - prev - 1)
            prev = num
    loss_data[label]["duplicates"] = duplicates
    loss_data[label]["losses"] = losses

# --- Graphique 1 : Taille moyenne des paquets UDP et QUIC ---

labels_x = list(pcap_files.keys())
udp_avgs = []
quic_avgs = []
for label in labels_x:
    udp_avgs.append(np.mean(size_data[label]["udp"]) if size_data[label]["udp"] else 0)
    quic_avgs.append(np.mean(size_data[label]["quic"]) if size_data[label]["quic"] else 0)

x = np.arange(len(labels_x))
width = 0.35

fig, ax = plt.subplots(figsize=(8, 6))
rects1 = ax.bar(x - width / 2, udp_avgs, width, label="UDP", color='lightblue')
rects2 = ax.bar(x + width / 2, quic_avgs, width, label="QUIC", color='lightgreen')

ax.set_ylabel("Taille moyenne des paquets (octets)")
ax.set_title("Taille moyenne des paquets UDP et QUIC")
ax.set_xticks(x)
ax.set_xticklabels(labels_x)
ax.legend()

for rect in rects1 + rects2:
    height = rect.get_height()
    ax.annotate(f'{height:.0f}',
                xy=(rect.get_x() + rect.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha='center', va='bottom')
plt.tight_layout()
plt.show()

# --- Graphique 2 : Nombre de doublons et pertes dans QUIC ---

duplicates_vals = [loss_data[label]["duplicates"] for label in labels_x]
losses_vals = [loss_data[label]["losses"] for label in labels_x]

fig, ax = plt.subplots(figsize=(8, 6))
rects1 = ax.bar(x - width / 2, duplicates_vals, width, label="Doublons", color='salmon')
rects2 = ax.bar(x + width / 2, losses_vals, width, label="Pertes", color='orange')

ax.set_ylabel("Nombre")
ax.set_title("Doublons et pertes (gaps) dans la numérotation des paquets QUIC")
ax.set_xticks(x)
ax.set_xticklabels(labels_x)
ax.legend()

for rect in rects1 + rects2:
    height = rect.get_height()
    ax.annotate(f'{height}',
                xy=(rect.get_x() + rect.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha='center', va='bottom')
plt.tight_layout()
plt.show()
