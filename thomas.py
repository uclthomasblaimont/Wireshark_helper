import pyshark
import matplotlib.pyplot as plt

# Chemin vers votre fichier pcapng
pcap_file = 'Thomas_Capture/thomas_wifi_planA3.pcapng'
capture = pyshark.FileCapture(pcap_file, keep_packets=False)

# Initialisation des compteurs de volume (en octets)
volume_tls = 0
volume_udp = 0
volume_tcp = 0
volume_stun = 0

# Parcours des paquets
for packet in capture:
    try:
        pkt_length = int(packet.length)
    except AttributeError:
        continue

    # Vérifier si le paquet contient TLS
    if hasattr(packet, 'tls'):
        volume_tls += pkt_length

    # Vérifier si le paquet contient UDP
    if hasattr(packet, 'udp'):
        volume_udp += pkt_length

    # Vérifier si le paquet contient TCP
    if hasattr(packet, 'tcp'):
        volume_tcp += pkt_length

    # Vérifier si le paquet contient STUN (souvent dans la couche 'stun')
    # Remarque : Certains paquets STUN sont encapsulés dans UDP
    if hasattr(packet, 'stun'):
        volume_stun += pkt_length

capture.close()

# Affichage des résultats
print("Volume de données par protocole (en octets) :")
print("TLS:", volume_tls)
print("UDP:", volume_udp)
print("TCP:", volume_tcp)
print("STUN:", volume_stun)

# Visualisation : création d'un diagramme à barres
protocols = ['TLS', 'UDP', 'TCP', 'STUN']
volumes = [volume_tls, volume_udp, volume_tcp, volume_stun]

plt.figure(figsize=(8, 5))
bars = plt.bar(protocols, volumes, color=['skyblue', 'lightgreen', 'salmon', 'orange'])
plt.xlabel("Protocoles")
plt.ylabel("Volume de données (octets)")
plt.title("Volume de données par protocole")
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, height, f'{height}', ha='center', va='bottom')
plt.show()
