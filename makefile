# Makefile

# Variable qui définit le fichier PCAP à analyser
PCAP_FILE ?= sample.pcap

# Cible "install" : installe les dépendances Python requises (pyshark)
install:
	pip install pyshark

# Cible "run" : lance l'analyse (via le script .sh), en utilisant la variable PCAP_FILE
run:
	./analyze_pcap.sh $(PCAP_FILE)

# Cible par défaut (si vous lancez juste "make")
# On peut la faire pointer vers "install" ou "help" ou autre
default: help

# Cible "help" : affiche les commandes disponibles
help:
	@echo "Cibles disponibles :"
	@echo "  install    -> Installe les dépendances (pyshark)"
	@echo "  run        -> Lance l'analyse sur le fichier PCAP (défini par PCAP_FILE)"
	@echo "  clean      -> Exemples de nettoyage, si nécessaire"
	@echo "  help       -> Affiche cette aide"

# Cible "clean" : exemple si vous aviez des fichiers à nettoyer
clean:
	rm -f *.pyc
	rm -rf __pycache__
