#!/usr/bin/env python3
"""
Orchestrateur de Maintenance Sécurisée.
Met en pause les sondes SOC, capture la nouvelle empreinte du site,
génère un snapshot de référence et réarme le bouclier.
"""

import requests
import hashlib
import os
import subprocess
import logging
from dotenv import load_dotenv
from reactor import creer_nouveau_snapshot

load_dotenv()

# Configuration standardisée des journaux (Logs d'audit)
logging.basicConfig(
    filename='/var/log/drac_maintenance.log',
    level=logging.INFO,
    format='%(asctime)s - [MAINTENANCE] - %(message)s'
)

IP_CIBLE = os.getenv("IP_CUEXI")
VMID_CIBLE = os.getenv("VMID_CUEXI")
NOEUD_PROXMOX = os.getenv("NOEUD_PROXMOX")
URL = f"http://{IP_CIBLE}"

NOM_SERVICE_DRAC = "drac.service"
NOM_SERVICE_WEBHOOK = "drac-webhook.service" # Service Wazuh à couper

def modifier_env(cle, nouvelle_valeur):
    """Fonction utilitaire pour modifier le coffre-fort .env en temps réel."""
    chemin_env = "/home/vm-ms-service/projet_ms/.env"
    try:
        with open(chemin_env, "r") as f:
            lignes = f.readlines()

        with open(chemin_env, "w") as f:
            for ligne in lignes:
                if ligne.startswith(f"{cle}="):
                    if cle == "HASH_ATTENDU":
                        f.write(f'{cle}="{nouvelle_valeur}"\n')
                    else:
                        f.write(f'{cle}={nouvelle_valeur}\n')
                else:
                    f.write(ligne)
    except Exception as e:
        logging.error(f"Erreur d'écriture dans le .env : {e}")
        print(f"[!] Erreur système lors de l'accès au coffre-fort : {e}")

def lancer_maintenance_cuexi():
    logging.info("Ouverture d'une fenêtre de maintenance par l'administrateur.")
    print("\n" + "="*60)
    print("      MODE MAINTENANCE SÉCURISÉ - CUEXI (SERVEUR WEB)      ")
    print("="*60 + "\n")

    try:
        # 1. Neutralisation des défenses (Pour éviter les fausses alertes)
        print("[*] Étape 1 : Suspension des boucliers (Démon local & Webhook Wazuh)...")
        subprocess.run(["sudo", "systemctl", "stop", NOM_SERVICE_DRAC], check=False)
        subprocess.run(["sudo", "systemctl", "stop", NOM_SERVICE_WEBHOOK], check=False)
        modifier_env("MAINTENANCE_CUEXI", "ON")
        logging.info("Sondes désactivées. Le système est en mode maintenance.")

        # 2. Fenêtre d'intervention humaine
        print("\n[!] ATTENTION : Le site Web N'EST PLUS sous surveillance.")
        print(f"[*] Vous pouvez modifier le code HTML sur la VM {IP_CIBLE} en toute sécurité.")
        input("⚠️ ACTION REQUISE : Appuyez sur [ENTRÉE] lorsque le nouveau site est en ligne et validé...")

        # 3. Calcul de la nouvelle empreinte cryptographique
        print("\n[*] Étape 2 : Génération de la nouvelle baseline de sécurité...")
        print(f"⏳ Téléchargement du nouveau code source depuis {URL}...")
        reponse = requests.get(URL, timeout=10)
        contenu = reponse.content 
        
        nouveau_hash = hashlib.sha256(contenu).hexdigest()
        print(f"[✅ SUCCÈS] Nouvelle empreinte SHA-256 générée : {nouveau_hash}")
        logging.info(f"Nouvelle empreinte validée : {nouveau_hash}")

        # 4. Mise à jour du système
        print("[*] Étape 3 : Mise à jour du coffre-fort des secrets (.env)...")
        modifier_env("HASH_ATTENDU", nouveau_hash)
        modifier_env("MAINTENANCE_CUEXI", "OFF")
        print("[OK] Secrets mis à jour.")

        # 5. Création de la référence Proxmox
        print("\n[*] Étape 4 : Injection via API Proxmox pour le nouveau 'REF_SAIN'...")
        if creer_nouveau_snapshot(NOEUD_PROXMOX, VMID_CIBLE):
            print("[✅ SUCCÈS] Arbre des snapshots mis à jour sur l'hyperviseur.")
        else:
            print("[❌ ERREUR] L'API Proxmox a refusé la création du snapshot.")

        # 6. Réarmement des défenses
        print(f"\n[*] Étape 5 : Réarmement des services de sécurité...")
        subprocess.run(["sudo", "systemctl", "start", NOM_SERVICE_DRAC], check=False)
        subprocess.run(["sudo", "systemctl", "start", NOM_SERVICE_WEBHOOK], check=False)
        
        logging.info("Clôture de la fenêtre de maintenance. Boucliers réarmés.")
        print("\n🛡️ [OK] OPÉRATION TERMINÉE. Le site Cuexi est de nouveau protégé à 100 %.")

    except Exception as e:
        logging.critical(f"Crash critique durant la maintenance : {e}")
        print(f"\n[❌ ERREUR CRITIQUE] Interruption inattendue : {e}")
        
        # Gilet de sauvetage : on tente de rallumer le webhook pour ne pas laisser le système aveugle
        modifier_env("MAINTENANCE_CUEXI", "OFF")
        subprocess.run(["sudo", "systemctl", "start", NOM_SERVICE_WEBHOOK], check=False)
        print("⚠️ [SÉCURITÉ] Le webhook Wazuh a été réactivé par sécurité. Vérifiez manuellement l'état du démon local.")

if __name__ == "__main__":
    lancer_maintenance_cuexi()
