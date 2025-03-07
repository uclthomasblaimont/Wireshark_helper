import pyshark
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter

# Remplacez 'votre_fichier.pcapng' par le chemin de votre fichier pcapng
capture = pyshark.FileCapture('Thomas_Capture/thomas_wifi_planA3.pcapng', keep_packets=False)

packet_sizes = []
timestamps = []

# Extraction des tailles et des timestamps
for packet in capture:
    try:
        # On suppose que le champ "length" contient la taille du paquet
        packet_sizes.append(int(packet.length))
        timestamps.append(float(packet.sniff_timestamp))
    except AttributeError:
        # Certains paquets pourraient ne pas avoir le champ length
        continue

capture.close()

# Affichage de la distribution des tailles de paquets
plt.figure(figsize=(10, 4))
plt.hist(packet_sizes, bins=50, color='skyblue', edgecolor='black')
plt.xlabel("Taille du paquet (octets)")
plt.ylabel("Fréquence")
plt.title("Distribution des tailles de paquets")
plt.show()

# Pour visualiser la fréquence des paquets dans le temps,
# on peut créer un histogramme en regroupant les paquets par intervalle de temps
start_time = min(timestamps)
end_time = max(timestamps)
bins = np.linspace(start_time, end_time, num=50)  # Ajustez le nombre de bins selon vos besoins

plt.figure(figsize=(10, 4))
plt.hist(timestamps, bins=bins, color='lightgreen', edgecolor='black')
plt.xlabel("Timestamp (secondes)")
plt.ylabel("Nombre de paquets")
plt.title("Fréquence des paquets dans le temps")
plt.show()
