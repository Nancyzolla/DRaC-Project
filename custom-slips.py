#!/usr/bin/env python3
import os
import time
import json
import requests
import glob

WEBHOOK_URL = "http://127.0.0.1:5000/slips-alert"
BASE_DIR = "/home/vm-ms-service/projet_ms/slips_output/"

def trouver_dernier_fichier():
    # Cherche tous les dossiers générés par SLIPS
    dossiers = glob.glob(os.path.join(BASE_DIR, 'ens18_*'))
    if not dossiers:
        return None
    # Trouve le plus récent
    dernier_dossier = max(dossiers, key=os.path.getmtime)
    fichier = os.path.join(dernier_dossier, 'alerts', 'alerts.json')
    return fichier if os.path.exists(fichier) else None

print("🌉 Démarrage du pont SLIPS -> DRaC...")
fichier_alerte = trouver_dernier_fichier()

while not fichier_alerte:
    time.sleep(2)
    fichier_alerte = trouver_dernier_fichier()

print(f"👁️ Fichier de l'IA trouvé ! Écoute en direct sur : {fichier_alerte}")

with open(fichier_alerte, 'r') as f:
    # On va à la fin du fichier pour écouter les NOUVELLES alertes
    while True:
        ligne = f.readline()
        if not ligne:
            time.sleep(1)
            continue
        try:
            alerte = json.loads(ligne.strip())
            print(f"🚀 Nouvelle alerte interceptée ! Envoi au Webhook...")
            requests.post(WEBHOOK_URL, json=alerte)
        except json.JSONDecodeError:
            pass
