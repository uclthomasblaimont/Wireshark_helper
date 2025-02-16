#!/usr/bin/env bash

# analyze_pcap.sh
# Usage: ./analyze_pcap.sh fichier.pcap

if [ $# -lt 1 ]; then
  echo "Usage: $0 <fichier_pcap>"
  exit 1
fi

PCAP_FILE=$1

python3 -c "
import sys
from analyze_pcap import analyze_capture

pcap_path = sys.argv[1]
analyze_capture(pcap_path, 'analysis.csv')
" "$PCAP_FILE"
