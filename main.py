#!/usr/bin/env python3
"""
Orchestrateur Principal DRaC (Dynamic Recovery and Containment).
Démon de supervision en temps réel (Disponibilité, Services, Intégrité).
"""

import time
import os
import logging
from dotenv import load_dotenv
from detector import ping_machine, verifier_port, verifier_hash_web
from reactor import restaurer_snapshot, demarrer_vm, remedier_douce_ssh
from notifier import alerte_panne_reseau, alerte_securite_defacage, alerte_resolution

# Chargement sécurisé du coffre-fort
load_dotenv()

# --- CONFIGURATION DYNAMIQUE DE LA CIBLE ---
IP_CIBLE = os.getenv("IP_CUEXI")
VMID_CIBLE = os.getenv("VMID_CUEXI")
NOEUD_PROXMOX = os.getenv("NOEUD_PROXMOX")
NOM_CIBLE = "vm-cucu-test"
HASH_ATTENDU = os.getenv("HASH_ATTENDU", "").replace('"', '')

# Configuration de la traçabilité SOC (Logs)
logging.basicConfig(
    filename='/var/log/drac_main.log',
    level=logging.INFO,
    format='%(asctime)s - [DRaC-ORCHESTRATOR] - %(levelname)s - %(message)s'
)

def demarrer_supervision():
    """Démon principal : Analyse continue de la cible et orchestration des remédiations."""
    logging.info(f"DÉMARRAGE DU BOUCLIER DRaC. Supervision active sur {NOM_CIBLE} ({IP_CIBLE}).")
    
    incident_en_cours = False

    while True:
        try:
            # === ÉTAPE 1 : SURVEILLANCE INFRASTRUCTURE (ICMP) ===
            if not ping_machine(IP_CIBLE):
                if not incident_en_cours:
                    logging.critical(f"Perte de connectivité critique sur {NOM_CIBLE} (Ping KO).")
                    alerte_panne_reseau(NOM_CIBLE, IP_CIBLE)
                    incident_en_cours = True

                logging.warning(f"[{NOM_CIBLE}] Ordre d'amorçage à froid envoyé à l'hyperviseur.")
                demarrer_vm(NOEUD_PROXMOX, VMID_CIBLE, NOM_CIBLE)
                time.sleep(60) # Temporisation d'amorçage OS
                continue

            # === ÉTAPE 2 : SURVEILLANCE SERVICE (TCP/80) ===
            if not verifier_port(IP_CIBLE, 80):
                logging.warning(f"Service Web injoignable sur {NOM_CIBLE} (Port 80 fermé).")
                
                # Remédiation de niveau 1 (Douce)
                if remedier_douce_ssh(IP_CIBLE, "drac_user"):
                    logging.info("Remédiation douce réussie. Vérification de la stabilité...")
                    time.sleep(10)
                    if verifier_port(IP_CIBLE, 80):
                        continue
                
                logging.error(f"Échec de la remédiation douce sur {NOM_CIBLE}. Escalade requise.")

            # === ÉTAPE 3 : SURVEILLANCE SÉCURITÉ (INTÉGRITÉ SHA-256) ===
            url_cible = f"http://{IP_CIBLE}"
            if not verifier_hash_web(url_cible, HASH_ATTENDU):
                if not incident_en_cours:
                    logging.critical(f"VIOLATION D'INTÉGRITÉ DÉTECTÉE sur {url_cible}.")
                    alerte_securite_defacage(NOM_CIBLE, url_cible)
                    incident_en_cours = True

                logging.warning(f"Déclenchement du Playbook SOC : Restauration de l'état sain sur {NOM_CIBLE}.")
                restaurer_snapshot(NOEUD_PROXMOX, VMID_CIBLE, NOM_CIBLE)
                time.sleep(120) # Temporisation pour l'application du Rollback
                continue

            # === ÉTAPE 4 : NORMALITÉ ET CLÔTURE D'INCIDENT ===
            if incident_en_cours:
                logging.info(f"RÉSOLUTION : Le système {NOM_CIBLE} est de nouveau sécurisé et opérationnel.")
                alerte_resolution(NOM_CIBLE, IP_CIBLE)
                incident_en_cours = False

            logging.debug(f"Routine de vérification terminée. {NOM_CIBLE} est sain.")
            time.sleep(15)

        except Exception as e:
            logging.error(f"Défaillance inattendue de l'orchestrateur DRaC : {e}")
            time.sleep(15)

if __name__ == "__main__":
    demarrer_supervision()
