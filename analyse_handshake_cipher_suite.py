import pyshark
import matplotlib.pyplot as plt

# Dictionnaire de correspondance pour les cipher suites TLS connues
cipher_suite_mapping = {
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xcca9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "0xcca8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "0xc00a": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "0xc009": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "0xc013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "0xc014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "0x009c": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "0x009d": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA"
}

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

# Initialisation des ensembles pour stocker les versions TLS et le dictionnaire pour compter les occurrences des cipher suites
tls_versions = set()
cipher_count = {}

print("=== Analyse TLS Handshake ===")
for pcap_file in pcap_files:
    print(f"Analyse TLS dans le fichier : {pcap_file}")
    # Filtrage sur les messages TLS handshake
    capture = pyshark.FileCapture(pcap_file, display_filter='tls.handshake', keep_packets=False)
    for packet in capture:
        if hasattr(packet, 'tls'):
            # Extraction de la version TLS
            try:
                version = packet.tls.record_version
                tls_versions.add(version)
            except AttributeError:
                pass

            # Extraction de la cipher suite négociée
            try:
                cs = packet.tls.handshake_ciphersuite
                cs_str = str(cs).lower()  # conversion en chaîne minuscule pour uniformiser
                # Ne compter que les cipher suites connues
                if cs_str in cipher_suite_mapping:
                    cs_name = cipher_suite_mapping[cs_str]
                    cipher_count[cs_name] = cipher_count.get(cs_name, 0) + 1
            except AttributeError:
                pass
    capture.close()

# Affichage des versions TLS observées
print("Versions TLS observées:")
for v in tls_versions:
    print(" -", v)

# Affichage des cipher suites négociées (uniquement celles connues)
print("\nCipher Suites (algorithmes de chiffrement) négociées (connues) :")
for cs, count in cipher_count.items():
    print(f" - {cs}: {count} occurrence(s)")

# Visualisation des occurrences des cipher suites TLS connues
if cipher_count:
    labels = list(cipher_count.keys())
    counts = list(cipher_count.values())

    plt.figure(figsize=(12, 6))
    bars = plt.bar(labels, counts, color='purple')
    plt.xlabel("Cipher Suite")
    plt.ylabel("Nombre d'occurrences")
    plt.title("Occurrences des Cipher Suites TLS (connues)")
    plt.xticks(rotation=45, ha='right')
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height, f'{height}', ha='center', va='bottom')
    plt.tight_layout()
    plt.show()
else:
    print("Aucune information de cipher suite connue n'a été trouvée.")
