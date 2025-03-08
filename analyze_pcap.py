#!/usr/bin/env python3
import pyshark
import csv

def analyze_packet(packet):
    """
    Analyse un paquet pour en extraire :
      - la couche réseau (IP source, IP destination, protocole)
      - la couche transport (TCP/UDP, ports)
      - la détection de chiffrement (ex: TLS/SSL)
    """
    infos = {}

    # Couche réseau (IP, protocole)
    if hasattr(packet, 'ip'):
        infos['ip_src'] = packet.ip.src
        infos['ip_dst'] = packet.ip.dst
        infos['proto']  = packet.ip.proto   # 6 = TCP, 17 = UDP, etc.
    elif hasattr(packet, 'ipv6'):
        infos['ip_src'] = packet.ipv6.src
        infos['ip_dst'] = packet.ipv6.dst
        infos['proto']  = packet.ipv6.nxt
    else:
        # Pas de couche IP (ARP ou autre protocole)
        infos['ip_src'] = 'N/A'
        infos['ip_dst'] = 'N/A'
        infos['proto']  = 'N/A'

    # Couche transport (TCP/UDP)
    if hasattr(packet, 'tcp'):
        infos['transport'] = 'TCP'
        infos['src_port']  = packet.tcp.srcport
        infos['dst_port']  = packet.tcp.dstport
    elif hasattr(packet, 'udp'):
        infos['transport'] = 'UDP'
        infos['src_port']  = packet.udp.srcport
        infos['dst_port']  = packet.udp.dstport
    else:
        infos['transport'] = 'Autre'
        infos['src_port']  = 'N/A'
        infos['dst_port']  = 'N/A'

    # Détection du chiffrement (TLS/SSL)
    if hasattr(packet, 'tls'):
        infos['encryption'] = 'TLS'
    elif hasattr(packet, 'ssl'):
        infos['encryption'] = 'SSL'
    else:
        # Vérification sommaire : port 443 -> TLS probable
        if (infos.get('transport') == 'TCP'
           and (infos.get('src_port') == '443' or infos.get('dst_port') == '443')):
            infos['encryption'] = 'TLS (443 suspecté)'
        else:
            infos['encryption'] = 'Non chiffré ou inconnu'

    return infos

def print_packet_info(pkt_info, index):
    """ Affiche les informations extraites d'un paquet dans le terminal. """
    print(f"\n=== Paquet n°{index} ===")
    print(f"  IP source      : {pkt_info['ip_src']}")
    print(f"  IP destination : {pkt_info['ip_dst']}")
    print(f"  Protocole IP   : {pkt_info['proto']}")
    print(f"  Transport      : {pkt_info['transport']}")
    print(f"  Port source    : {pkt_info['src_port']}")
    print(f"  Port dest      : {pkt_info['dst_port']}")
    print(f"  Chiffrement    : {pkt_info['encryption']}")

def analyze_capture(file_path, csv_path='analysis.csv'):
    """
    Ouvre un fichier PCAP et analyse chaque paquet :
      - Affichage sur le terminal
      - Écriture des résultats dans un fichier CSV
    """
    print(f"\nAnalyse de la capture : {file_path}")

    # Ouverture de la capture
    capture = pyshark.FileCapture(file_path)

    # Ouverture (en écriture) d'un fichier CSV
    # newline='' pour éviter les lignes vides sur certains OS
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Écriture de l'entête
        writer.writerow([
            "Index", "IP_source", "IP_destination", "Protocole_IP",
            "Transport", "Port_source", "Port_destination", "Chiffrement"
        ])

        # Parcours de chaque paquet
        for i, packet in enumerate(capture, start=1):
            try:
                pkt_info = analyze_packet(packet)
                # Affichage terminal
                print_packet_info(pkt_info, i)

                # Écriture CSV (même ordre que le header)
                writer.writerow([
                    i,
                    pkt_info['ip_src'],
                    pkt_info['ip_dst'],
                    pkt_info['proto'],
                    pkt_info['transport'],
                    pkt_info['src_port'],
                    pkt_info['dst_port'],
                    pkt_info['encryption']
                ])
            except Exception as e:
                print(f"\n[!] Erreur lors de l'analyse du paquet n°{i} : {e}")

    capture.close()
    print(f"\nAnalyse terminée. Résultats enregistrés dans : {csv_path}")


import pyshark


def capture_tls_cipher_suites(interface='eth0', max_packets=10):
    """
    Capture des paquets TLS sur une interface et retourne
    la liste des cipher suites détectées dans le handshake TLS.

    :param interface: Nom de l'interface réseau à écouter (ex: 'eth0', 'wlan0', etc.)
    :param max_packets: Nombre maximal de paquets à analyser avant d'arrêter la capture.
    :return: Liste des cipher suites détectées.
    """
    cipher_suites = []

    # On applique un filtre Wireshark pour ne récupérer que les paquets TLS.
    capture = pyshark.LiveCapture(interface=interface, display_filter='tls')

    # Parcours des paquets en temps réel, limité par max_packets
    for i, packet in enumerate(capture.sniff_continuously()):
        if i >= max_packets:
            break

        # Vérifier que le paquet contient un segment TLS
        if 'TLS' in packet:
            tls_layer = packet.tls
            # Vérifier l'attribut contenant la suite de chiffrement
            if hasattr(tls_layer, 'handshake_ciphersuite'):
                suite = tls_layer.handshake_ciphersuite
                cipher_suites.append(suite)

    return cipher_suites


if __name__ == "__main__":
    # Exemple d'utilisation
    suites = capture_tls_cipher_suites(interface='eth0', max_packets=20)
    print("Cipher suites TLS détectées :")
    for s in suites:
        print(f" - {s}")
