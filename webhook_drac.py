#!/usr/bin/env python3
"""
Webhook DRaC (Dynamic Recovery and Containment) - API SOC.
Interface d'écoute (Flask) pour les alertes HIDS (Wazuh) et NIDS (Slips/IA).
Orchestre les playbooks de remédiation en fonction de la gravité des événements.
"""

import os
import re
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Imports des modules SOC (Réaction et Notification)
from reactor import restaurer_snapshot, isoler_reseau_vm, bloquer_ip_via_proxmox
from notifier import envoyer_mail_formate

# Configuration standardisée des journaux (Logs d'audit)
logging.basicConfig(
    filename='/var/log/drac_webhook.log',
    level=logging.INFO,
    format='%(asctime)s - [WEBHOOK-SOC] - %(levelname)s - %(message)s'
)

app = Flask(__name__)

def verifier_maintenance():
    """
    Vérifie l'état du verrou de maintenance.
    Si actif, les alertes de sécurité sont ignorées pour éviter les faux positifs.
    """
    load_dotenv("/home/vm-ms-service/projet_ms/.env", override=True)
    return os.getenv("MAINTENANCE_CUEXI") == "ON"

# =====================================================================
# ROUTE 1 : DÉTECTION SYSTÈME (WAZUH - HIDS)
# =====================================================================
@app.route('/wazuh-alert', methods=['POST'])
def gerer_alerte_wazuh():
    donnees_alerte = request.json
    if not donnees_alerte:
        return jsonify({"error": "Payload vide"}), 400

    groupes_regle = donnees_alerte.get('rule', {}).get('groups', [])
    description_regle = donnees_alerte.get('rule', {}).get('description', 'Inconnue')
    niveau_alerte = donnees_alerte.get('rule', {}).get('level', 0)
    
    # Variables d'environnement cibles
    vmid = os.getenv("VMID_CUEXI")
    noeud = os.getenv("NOEUD_PROXMOX")
    nom_vm = "vm-cucu-test"

    # --- LE PRINT LOGS POUR TON TERMINAL ---
    print(f"\n🚨 [WAZUH - SYSTÈME] Alerte interceptée : {description_regle} (Niveau {niveau_alerte})")
    logging.info(f"Alerte Wazuh interceptée : {description_regle} (Niveau {niveau_alerte})")

    if verifier_maintenance():
        print("🚧 [MAINTENANCE] Alerte ignorée : Le système est en mode maintenance planifiée.")
        logging.info("Alerte ignorée : Le système est en mode maintenance planifiée.")
        return jsonify({"statut": "ignore_maintenance"}), 200

# ---------------------------------------------------------
    # SCÉNARIO A : Compromission de Fichiers (FIM / Défaçage)
    # ---------------------------------------------------------
    if "syscheck" in groupes_regle or "syscheck" in donnees_alerte:
        fichier = donnees_alerte.get('syscheck', {}).get('path', '')
        if "/var/www/html" in fichier or "/etc/" in fichier:
            logging.critical(f"Violation d'intégrité (FIM) sur {fichier}. Lancement du Playbook Restauration.")

            # Mail d'alerte immédiate
            sujet_alerte = f"⚠️ [DRaC-SOAR] INCIDENT CRITIQUE - Défaçage sur {nom_vm}"
            corps_alerte = (
                "============================================================\n"
                "🚨 ALERTE DE SÉCURITÉ CRITIQUE - DÉFAÇAGE DÉTECTÉ\n"
                "============================================================\n\n"
                f"Sonde : Wazuh HIDS (File Integrity Monitoring)\n"
                f"Cible : {nom_vm} (ID: {vmid})\n"
                f"Fichier compromis : {fichier}\n\n"
                "Le DRaC lance IMMÉDIATEMENT la procédure de capture forensique "
                "et de restauration depuis la sauvegarde saine de référence."
            )
            envoyer_mail_formate(sujet_alerte, corps_alerte)

            # --- C'EST CETTE LIGNE QUI AVAIT DISPARU ---
            # Restauration automatisée
            restaurer_snapshot(noeud, vmid, nom_vm)

            # Mail de résolution
            sujet_ok = f"✅ [DRaC-SOAR] RESTAURATION RÉUSSIE - {nom_vm} sécurisé"
            corps_ok = (
                "============================================================\n"
                "♻️ FIN DE L'INCIDENT - SYSTÈME RESTAURÉ ET SAIN\n"
                "============================================================\n\n"
                "Rapport du module Reactor :\n"
                "- Capture de la scène de crime sauvegardée sur l'hyperviseur.\n"
                "- Système restauré depuis la baseline 'REF_SAIN'.\n"
                "- Services Web de nouveau opérationnels."
            )
            envoyer_mail_formate(sujet_ok, corps_ok)
            
            # --- NOTIFICATION SUR TON TERMINAL ---
            print(f"✅ [DRaC-SOAR] Fin de l'incident : {nom_vm} a été restauré avec succès et le réseau est rétabli.")
            
            return jsonify({"statut": "restauration_effectuee"}), 200
    # ---------------------------------------------------------
    # SCÉNARIO B : Attaque de surface (Brute Force SSH)
    # ---------------------------------------------------------
    elif niveau_alerte >= 10 and ("authentication_failed" in groupes_regle or "brute force" in description_regle.lower() or "failed" in description_regle.lower()):
        logging.warning(f"Attaque de surface détectée : {description_regle}")

        # Extraction robuste de l'IP
        bloc_data = donnees_alerte.get('data', {})
        ip_attaquant = bloc_data.get('srcip') or bloc_data.get('src_ip') or donnees_alerte.get('srcip')

        if not ip_attaquant:
            match = re.search(r'from\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})', str(donnees_alerte))
            if match:
                ip_attaquant = match.group(1)

        if not ip_attaquant or ip_attaquant == 'Inconnue':
            logging.error("Brute Force détecté mais impossible d'extraire l'IP source.")
            return jsonify({"statut": "ip_introuvable"}), 200

        # Liste blanche (Whitelist)
        if ip_attaquant in ["10.10.0.124", os.getenv("PROXMOX_HOST")]:
            logging.info(f"IP {ip_attaquant} sur liste blanche. Ignorée.")
            return jsonify({"statut": "ignore_whitelist"}), 200

        logging.warning(f"Lancement du confinement réseau pour l'IP : {ip_attaquant}")
        if bloquer_ip_via_proxmox(ip_attaquant, vmid, noeud):
            sujet = f"🚨 [DRaC] CONFINEMENT APPLIQUÉ - IP {ip_attaquant} bannie"
            corps = (
                "============================================================\n"
                "🔒 NOTIFICATION DE BANNISSEMENT IP - DRaC SOAR\n"
                "============================================================\n\n"
                f"Gravité : Niveau {niveau_alerte}\n"
                f"Menace : Tentative d'intrusion (Brute Force) par l'IP [{ip_attaquant}]\n\n"
                "Action appliquée : Le Pare-feu Proxmox a été configuré pour rejeter "
                "automatiquement tout le trafic provenant de cette adresse."
            )
            envoyer_mail_formate(sujet, corps)
            print(f"✅ [DRaC-SOAR] Fin de l'incident : L'IP hostile {ip_attaquant} a été bannie définitivement du pare-feu.")
        return jsonify({"statut": "ip_bannie", "ip": ip_attaquant}), 200

    # ---------------------------------------------------------
    # SCÉNARIO C : Compromission interne (Élévation Privilèges)
    # ---------------------------------------------------------
    elif "sudo" in groupes_regle and niveau_alerte >= 5:
        logging.critical(f"Activité suspecte (SUDO) détectée. Risque interne majeur. Lancement isolation réseau.")
        
        if isoler_reseau_vm(noeud, vmid, nom_vm):
            sujet = f"🛑 [DRaC-SOAR] INCIDENT MAJEUR - Isolation réseau de {nom_vm}"
            corps = (
                "============================================================\n"
                "🛑 NOTIFICATION D'ISOLEMENT D'URGENCE - DRaC SOAR\n"
                "============================================================\n\n"
                "DÉTECTION :\n"
                "- Module : Wazuh-HIDS (Surveillance Sudo/Root)\n"
                f"- Gravité : Critique (Niveau {niveau_alerte})\n"
                f"- Détail technique : {description_regle}\n\n"
                "ACTION DE REMÉDIATION APPLIQUÉE :\n"
                "Risque de compromission interne (Élévation de privilèges).\n"
                "Le module Reactor a procédé au débranchement virtuel immédiat de la carte "
                "réseau (Link Down) sur l'hyperviseur pour confiner l'infection.\n\n"
                "STATUT : Serveur totalement isolé du réseau. Intervention manuelle requise."
            )
            envoyer_mail_formate(sujet, corps)
            print(f"✅ [DRaC-SOAR] Fin de l'incident : {nom_vm} a été isolée du réseau mondial (Mise en quarantaine).")
        return jsonify({"statut": "isolation_totale"}), 200

    return jsonify({"statut": "journalise", "niveau": niveau_alerte}), 200

# =====================================================================
# ROUTE 2 : DÉTECTION RÉSEAU INTELLIGENTE (SLIPS - NIDS / ML)
# =====================================================================
# Mémoire pour éviter de spammer Proxmox et la boîte mail
memoire_ips_bannies = set()
@app.route('/slips-alert', methods=['POST'])
def gerer_alerte_slips():
    global memoire_ips_bannies

    data = request.json
    if not data:
        return jsonify({"error": "Payload vide"}), 400

    severity = data.get("Severity", "Unknown")
    description = data.get("Description", "Attaque réseau détectée")

    try:
        ip_attaquant = data["Source"][0]["IP"]
    except (KeyError, TypeError, IndexError):
        ip_attaquant = "Inconnue"

    logging.info(f"Alerte SLIPS interceptée : IP {ip_attaquant} (Gravité: {severity})")

    # =========================================================
    # 🛡️ LISTE BLANCHE (WHITELIST) : PROTECTION ANTI-SUICIDE
    # =========================================================
    IP_MS_SERVICE = "10.10.0.113"
    IP_CUEXI = os.getenv("IP_CUEXI")

    if ip_attaquant in memoire_ips_bannies:
        logging.info(f"♻️ L'IP {ip_attaquant} est DÉJÀ bannie. Alerte redondante ignorée.")
        return jsonify({"status": "already_banned"}), 200
    
    if ip_attaquant == IP_MS_SERVICE or ip_attaquant == IP_CUEXI or ip_attaquant == "127.0.0.1":
        logging.info(f"🛡️ [SÉCURITÉ] L'IA a ciblé notre propre serveur ({ip_attaquant}). Faux positif ignoré !")
        return jsonify({"status": "ignore_whitelist"}), 200
    # =========================================================

    if verifier_maintenance():
        logging.info("Alerte SLIPS ignorée en raison de la maintenance planifiée.")
        return jsonify({"statut": "ignore_maintenance"}), 200

    if severity == "High" and ip_attaquant != "Inconnue":
        logging.critical(f"Menace réseau IA détectée. Bannissement de l'IP {ip_attaquant}.")
        
        vmid = os.getenv("VMID_CUEXI")
        noeud = os.getenv("NOEUD_PROXMOX")

        if bloquer_ip_via_proxmox(ip_attaquant, vmid, noeud):
            memoire_ips_bannies.add(ip_attaquant)
            sujet = f"🚨 [DRaC-NIDS] BLOCAGE IA - IP {ip_attaquant} bannie"
            corps = (
                "============================================================\n"
                "🧠 NOTIFICATION DE BLOCAGE IA NETWORK - DRaC SOAR\n"
                "============================================================\n\n"
                "DÉTECTION AUTOMATIQUE :\n"
                "- Système : SLIPS (Analyseur comportemental IA / NIDS)\n"
                f"- Gravité : {severity} (Critique)\n"
                f"- Comportement : {description}\n\n"
                "ACTION DE REMÉDIATION APPLIQUÉE :\n"
                f"L'adresse IP externe [{ip_attaquant}] a été identifiée comme malveillante.\n"
                "Le Pare-feu Proxmox la rejette désormais automatiquement."
            )
            envoyer_mail_formate(sujet, corps)
            print(f"✅ [DRaC-SOAR] Fin de l'incident : Flux malveillant neutralisé, l'attaquant {ip_attaquant} est banni.")
            return jsonify({"status": "action_taken", "banned_ip": ip_attaquant}), 200

    logging.debug(f"Alerte SLIPS classée mineure ({severity}). Aucune action requise.")
    return jsonify({"status": "logged", "severity": severity}), 200
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
