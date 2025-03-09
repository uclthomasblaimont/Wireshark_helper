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