# DualWifi

## Chiffrement

### **Raison d'utilisation du protocole**
Dans une application comme Screego, **TLS** est probablement utilisé pour :

- **Sécuriser les communications** : Protéger les données échangées entre le host et le spectateur (par exemple, les flux vidéo ou les commandes de contrôle).
- **Authentifier le serveur** : S'assurer que les utilisateurs se connectent bien au bon serveur Screego et non à un serveur malveillant.
- **Protéger la confidentialité** : Empêcher quiconque d'intercepter et de lire les flux vidéo ou autres données sensibles.

---

### **Utilisation**
TLS est utilisé dans de nombreuses applications et protocoles, notamment :

- **HTTPS** : La version sécurisée du protocole HTTP, utilisée pour les sites web.
- **Applications peer-to-peer** : Des applications comme Screego peuvent utiliser TLS pour sécuriser les communications entre les pairs.

---

## Fonctionnement

### **Négociation des paramètres**
- Le client et le serveur se mettent d'accord sur la version de TLS à utiliser et sur les algorithmes de chiffrement (par exemple, AES, ChaCha20, etc.).
- Le serveur envoie son **certificat numérique** au client pour prouver son identité.

---

### **Échange de clés**
- Le client et le serveur échangent des informations pour générer une **clé de session symétrique**. Cette clé sera utilisée pour chiffrer et déchiffrer les données pendant la session.
- L'échange de clés peut se faire via des algorithmes comme **RSA**, **Diffie-Hellman (DH)** ou **Elliptic Curve Diffie-Hellman (ECDH)**.

---

### **Chiffrement des données**
- Une fois le handshake terminé, toutes les données échangées entre le client et le serveur sont chiffrées à l'aide de la clé de session symétrique.

---

## TLS

### **Côté Client**
- **Handshake Protocol** : `Client Hello` (si c'est le serveur, `Server Hello`).
- **Version** : TLS 1.2 (version maximale supportée par le client).
- **Random** : Nombre aléatoire généré par le client pour des raisons de sécurité.
- **Session ID** : Pour TLS v1.2 et les versions précédentes. Permet d'identifier une session TLS précédente et de la reprendre sans refaire tout le handshake à chaque fois.
- **Cipher Suite** : Tous les algorithmes de chiffrement supportés par le client.
- **Compression Methods** : Liste des méthodes de compression utilisées par le client. Dans notre cas, c'est déprécié pour des raisons de sécurité (dans la version 1.3, ce n'est pas utilisé).
- **Extensions TLS** : Sont des extensions optionnelles et servent à se mettre d'accord sur le secret partagé grâce à l'algorithme Diffie-Hellman. Grâce à l'extension `supported_version`, le serveur peut savoir quelles versions de TLS sont supportées par le client. Dans notre cas, TLS v1.2 et v1.3 sont supportés.

---

### **Côté Serveur**
- Côté serveur, c'est pareil, sauf que le serveur choisit l'algorithme de chiffrement : `TLS_AES_128_GCM_SHA256`.
- **Version choisie par le serveur** : TLS v1.3.
- Concernant les **records**, il y en a 3 côté serveur contre 1 côté client. Celui qui nous intéresse est le dernier record. Celui-ci contient des données chiffrées, y compris le certificat SSL et d'autres informations. Les données sont envoyées en plusieurs fois au client à cause de la taille de la fenêtre.

---

### **Fin du Handshake**
- Dès que le handshake est terminé, le client et le serveur se sont mis d'accord. Tout est mis à jour côté client et serveur.
- Un autre record apparaît côté client, contenant la requête HTTP chiffrée (paquet n°38).
- Les paquets suivants (à partir du paquet n°39) contiennent les requêtes HTTP du client et les réponses du serveur.

---

### **Résumé des paquets**
- **Paquet n°38** : Requête HTTP chiffrée côté client.
- **Paquets n°39 et suivants** : Échanges de requêtes HTTP client-serveur.

-
# Analyse des paquets STUN/TURN avec Screego

## **Adresses IP**
- **IP client** : `192.168.177.60`
- **IP serveur** : `49.13.207.241`

---

## **Étapes d'analyse**

### **1. Paquet 601 (Client) - Requête UDP**
- **Ports** : Source (`58776`) → Destination (`3478`)
- **Lifetime** : `3600` secondes (durée de vie de la session).
- **Type d'attribut** : `REQUESTED-TRANSPORT UDP`
  - Le client demande à utiliser **UDP** comme protocole de transport pour la communication.

---

### **2. Paquet 614 (Serveur) - Erreur 401 (Non autorisé)**
- **Erreur 401** : Le serveur refuse la requête UDP car l'authentification a échoué.
- **Redemande de requête** : Le client renvoie une nouvelle requête UDP au paquet `617`, similaire au paquet `601`.

---

### **3. Utilisation d'IPv6**
- **Pourquoi IPv6 ?** : Si une requête UDP via IPv4 n'obtient pas de réponse ou génère une erreur, Screego tente d'utiliser **IPv6** comme alternative.

---

### **4. Paquet 631 (Serveur) - Réponse ALLOCATE SUCCESS**
- **STUN Network Version** : `RFC-5389/8489` (version du protocole STUN utilisée).
- **Attributs** :
  - **XOR-RELAYED-ADDRESS** : Adresse IPv6 relayée par le serveur.
  - **XOR-MAPPED-ADDRESS** : `130.104.31.140:58779` (adresse IPv4 publique mappée par le NAT).

---

### **5. Paquet 742 (Client) - CreatePermission Request**
- **Attributs** :
  - **XOR-PEER-ADDRESS** : Adresse IPv6 du pair (peer).
  - **USERNAME** : `cv0rhrcn1r1c738a1ou0host` (identifiant de l'utilisateur).
  - **REALM** : `screego` (domaine d'authentification).
  - **NONCE** : Information chiffrée utilisée pour l'authentification.
  - **MESSAGE-INTEGRITY** : Vérification de l'intégrité du message.
  - **FINGERPRINT** : Type de compréhension du flag.

---

### **6. Paquet 743 (Client) - Send Indication**
- **Attributs** :
  - **XOR-PEER-ADDRESS** : Adresse IPv6 du pair.
  - **DATA** : `100 bytes` de données chiffrées.
  - **FINGERPRINT** : Type de compréhension du flag.

---

### **7. Paquet 748 (Serveur) - CreatePermission Success Response**
- **Attributs** :
  - **Message Type** : `0x0108` (réponse de succès).
  - **MESSAGE-INTEGRITY** : Vérification de l'intégrité du message.

---

### **8. Intervention d'ICMPv6**
- **Message ICMPv6** : `Destination Unreachable (Source address failed ingress/egress policy)`.
  - Cela signifie que la requête de binding (paquet `748`) a échoué en raison d'une politique de filtrage réseau (ingress/egress).

---

### **9. Paquet 768 (Serveur) - Binding Success Response**
- **Attributs** :
  - **XOR-MAPPED-ADDRESS** : `130.104.100.252:57388` (nouvelle adresse IPv4 mappée).
  - **MESSAGE-INTEGRITY** : Vérification de l'intégrité du message.
  - **FINGERPRINT** : Type de compréhension du flag.

---

### **10. Paquets 771-774 (Serveur) - DATA Indication**
- **Attributs** :
  - **XOR-PEER-ADDRESS** : Adresse IPv6 du client.
  - **DATA** : Données chiffrées envoyées au client.

---

### **11. Paquet 977 (Serveur) - Receiver Report**
- **Attributs** :
  - **XOR-PEER-ADDRESS** : Adresse IPv6 du client.
  - **DATA** : Données chiffrées contenant des informations RTCP (Real-Time Transport Control Protocol).
    - **RTCP** : Rapport sur les paquets perdus et d'autres détails pour 2 sources.

---

### **12. Paquet 992 (Client) - Sender Report**
- **Attributs** :
  - **XOR-PEER-ADDRESS** : Adresse IPv6 du client.
  - **DATA** : Données chiffrées contenant des informations RTCP.
    - **RTCP Sender Report** : Rapport d'envoi.
    - **RTCP Receiver Summary Information** : Résumé des informations de réception.
  - **FINGERPRINT** : Type de compréhension du flag.

---

### **13. Paquet 1705 (Client) - Refresh Request**
- **Attributs** :
  - **LIFETIME** : `0` (demande de fin de session).
  - **USERNAME** : `cv0rhrcn1r1c738a1ou0host`.
  - **REALM** : `screego`.
  - **NONCE** : Information chiffrée.
  - **MESSAGE-INTEGRITY** : Vérification de l'intégrité du message.
  - **FINGERPRINT** : Type de compréhension du flag.

---

### **14. Paquet 1725 (Serveur) - Refresh Error Response**
- **Erreur 400** : `Bad Request` (la requête de rafraîchissement est invalide).

---

### **15. Fin de session**
- **Flags TCP** : `[FIN, ACK]`
  - Le serveur envoie ces flags pour indiquer la fin de la session TCP.

---

## **Explications supplémentaires**

### **STUN et TURN**
- **STUN** : Utilisé pour découvrir les adresses IP publiques et faciliter les connexions directes entre pairs.
- **TURN** : Utilisé lorsque STUN ne parvient pas à établir une connexion directe (par exemple, à cause d'un NAT restrictif). TURN agit comme un relais pour transférer les données entre les pairs.

### **RTCP (Real-Time Transport Control Protocol)**
- **Rôle** : RTCP est utilisé pour surveiller la qualité de la transmission en temps réel (par exemple, le nombre de paquets perdus, la latence, etc.).
- **Utilisation dans Screego** : RTCP est utilisé pour gérer le flux vidéo en temps réel pendant le partage d'écran.

### **ICMPv6**
- **Rôle** : ICMPv6 est utilisé pour signaler des erreurs dans les communications IPv6.
- **Exemple** : Dans notre capture, ICMPv6 signale que la requête de binding a échoué en raison d'une politique de filtrage réseau.

---

## **Conclusion**
Notre analyse montre comment Screego utilise **STUN**, **TURN**, et **RTCP** pour établir et gérer des connexions peer-to-peer. Les erreurs (comme l'erreur 401 ou 400) et les interventions d'ICMPv6 mettent en évidence les défis liés aux NAT et aux politiques de filtrage réseau. La fin de session avec les flags TCP `[FIN, ACK]` confirme la fermeture propre de la connexion.
