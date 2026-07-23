#!/usr/bin/env python3
"""
Module de Détection et de Sonde (DRaC SOC).
Analyse l'état du réseau, des ports TCP et l'intégrité cryptographique des fichiers.
"""

import subprocess
import socket
import requests
import hashlib
import logging

# Configuration standardisée des journaux (Logs)
logging.basicConfig(
    filename='/var/log/drac_detector.log',
    level=logging.INFO,
    format='%(asctime)s - [DETECTOR] - %(levelname)s - %(message)s'
)

def ping_machine(ip):
    """Vérifie la disponibilité d'un hôte sur le réseau via ICMP (Ping)."""
    try:
        reponse = subprocess.run(
            ['ping', '-c', '1', '-W', '2', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return reponse.returncode == 0
    except Exception as e:
        logging.error(f"Échec de la sonde ICMP vers {ip} : {e}")
        return False

def verifier_port(ip, port):
    """Vérifie l'état d'un port TCP spécifique sur une machine cible."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        resultat = sock.connect_ex((ip, port))
        sock.close()
        return resultat == 0
    except Exception as e:
        logging.error(f"Échec de la vérification TCP sur {ip}:{port} - {e}")
        return False

def verifier_hash_web(url, hash_attendu):
    """
    Vérifie l'intégrité d'une page Web en comparant son empreinte (SHA-256).
    """
    try:
        reponse = requests.get(url, timeout=5)
        if reponse.status_code == 200:
            hash_actuel = hashlib.sha256(reponse.content).hexdigest()

            if hash_actuel != hash_attendu:
                logging.warning(f"Violation d'intégrité détectée sur {url} !")
                logging.debug(f"Attendu : {hash_attendu} | Actuel : {hash_actuel}")
                return False
            return True
        else:
            logging.warning(f"Code HTTP inattendu sur {url} : {reponse.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Impossible de joindre le serveur Web {url} : {e}")
        return False

# --- BLOC DE DIAGNOSTIC LOCAL ---
if __name__ == "__main__":
    print("[*] DÉMARRAGE DE L'OUTIL DE DIAGNOSTIC DES SONDES...")

    cible_test = "8.8.8.8"
    
    statut_ping = ping_machine(cible_test)
    print(f"[SONDE] Test ICMP vers {cible_test} : {'SUCCÈS' if statut_ping else 'ÉCHEC'}")

    statut_https = verifier_port(cible_test, 443)
    print(f"[SONDE] Test TCP (Port 443) vers {cible_test} : {'OUVERT' if statut_https else 'FERMÉ'}")

    statut_rdp = verifier_port(cible_test, 3389)
    print(f"[SONDE] Test TCP (Port 3389) vers {cible_test} : {'OUVERT' if statut_rdp else 'FERMÉ/FILTRÉ'}")

    print("[*] FIN DU DIAGNOSTIC.")
