import pyshark
import matplotlib.pyplot as plt

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
    # Ajoutez ici d'autres fichiers de capture si nécessaire
]

##############################################
# Partie 1 : Calcul du ratio IPv4 vs IPv6
##############################################

# Initialisation des compteurs
ipv4_count = 0
ipv6_count = 0

print("=== Analyse IPv4 vs IPv6 ===")
# Parcours de chaque fichier de capture
for pcap_file in pcap_files:
    print(f"Analyse du fichier : {pcap_file}")
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    for packet in capture:
        # Vérifier la présence d'une couche IPv4
        if hasattr(packet, 'ip'):
            ipv4_count += 1
        # Vérifier la présence d'une couche IPv6
        if hasattr(packet, 'ipv6'):
            ipv6_count += 1
    capture.close()

# Affichage des résultats pour IPv4/IPv6
print("Nombre de paquets IPv4:", ipv4_count)
print("Nombre de paquets IPv6:", ipv6_count)
if ipv4_count > 0:
    ratio = ipv6_count / ipv4_count
    print("Ratio IPv6 / IPv4:", ratio)
else:
    print("Aucun paquet IPv4 trouvé.")

# Visualisation avec un diagramme à barres pour IPv4 vs IPv6
labels = ['IPv4', 'IPv6']
counts = [ipv4_count, ipv6_count]

plt.figure(figsize=(6, 4))
bars = plt.bar(labels, counts, color=['blue', 'green'])
plt.xlabel("Type d'adresse IP")
plt.ylabel("Nombre de paquets")
plt.title("Comparaison du nombre de paquets IPv4 vs IPv6")
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2, height, f'{height}', ha='center', va='bottom')
plt.show()

##############################################
# Partie 2 : Extraction des informations de chiffrement TLS
##############################################

# Initialisation des ensembles pour stocker les versions TLS et les cipher suites
tls_versions = set()
cipher_suites = set()

print("\n=== Analyse TLS Handshake ===")
# Pour chaque fichier, on filtre uniquement sur les messages TLS handshake
# qui contiennent des informations sur le chiffrement.
for pcap_file in pcap_files:
    print(f"Analyse TLS dans le fichier : {pcap_file}")
    # On utilise le filtre d'affichage 'tls.handshake' pour ne récupérer que les messages de handshake TLS.
    capture = pyshark.FileCapture(pcap_file, display_filter='tls.handshake', keep_packets=False)
    for packet in capture:
        if hasattr(packet, 'tls'):
            # Extraction de la version TLS
            try:
                version = packet.tls.record_version
                tls_versions.add(version)
            except AttributeError:
                pass

            # Extraction de la cipher suite négociée (souvent dans le Server Hello)
            try:
                cs = packet.tls.handshake_ciphersuite
                cipher_suites.add(cs)
            except AttributeError:
                pass
    capture.close()

# Affichage des résultats TLS
print("Versions TLS observées:")
for v in tls_versions:
    print(" -", v)

print("\nCipher suites (algorithmes de chiffrement) négociées:")
for cs in cipher_suites:
    print(" -", cs)

# Visualisation des données TLS (diagramme à barres simple pour illustration)
# Ici, nous affichons le nombre d'occurrences pour chaque cipher suite si besoin.
# Nous allons re-parcourir les fichiers pour compter les occurrences.
cipher_count = {}

for pcap_file in pcap_files:
    capture = pyshark.FileCapture(pcap_file, display_filter='tls.handshake', keep_packets=False)
    for packet in capture:
        if hasattr(packet, 'tls'):
            try:
                cs = packet.tls.handshake_ciphersuite
                if cs in cipher_count:
                    cipher_count[cs] += 1
                else:
                    cipher_count[cs] = 1
            except AttributeError:
                continue
    capture.close()

if cipher_count:
    labels = list(cipher_count.keys())
    counts = list(cipher_count.values())

    plt.figure(figsize=(10, 6))
    bars = plt.bar(labels, counts, color='purple')
    plt.xlabel("Cipher Suite")
    plt.ylabel("Nombre d'occurrences")
    plt.title("Occurences des Cipher Suites TLS")
    plt.xticks(rotation=45, ha='right')
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height, f'{height}', ha='center', va='bottom')
    plt.tight_layout()
    plt.show()
else:
    print("Aucune information de cipher suite n'a été trouvée.")
