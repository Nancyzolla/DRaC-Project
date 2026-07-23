#!/usr/bin/env python3
"""
Module de Notification Sécurisée (DRaC SOC).
Gère l'envoi des rapports d'incidents et alertes via SMTP/TLS.
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Configuration standardisée des journaux (Logs)
logging.basicConfig(
    filename='/var/log/drac_notifier.log',
    level=logging.INFO,
    format='%(asctime)s - [NOTIFIER] - %(levelname)s - %(message)s'
)

# Chargement du coffre-fort de variables
load_dotenv("/home/vm-ms-service/projet_ms/.env", override=True)

def envoyer_mail_formate(sujet, corps):
    """
    Fonction centrale de notification.
    Établit un tunnel sécurisé vers le serveur SMTP pour transmettre l'alerte.
    """
    EXPEDITEUR = os.getenv("MAIL_USER")
    MOT_DE_PASSE = os.getenv("MAIL_PASS")
    DESTINATAIRE = os.getenv("MAIL_DEST")

    if not EXPEDITEUR or not MOT_DE_PASSE:
        logging.error("Configuration SMTP manquante dans le fichier .env.")
        return

    # Formatage professionnel du message MIME
    msg = MIMEMultipart()
    msg['Subject'] = sujet
    msg['From'] = f"DRaC Security <{EXPEDITEUR}>"
    msg['To'] = DESTINATAIRE
    
    corps_complet = f"""
    === SYSTÈME DRaC - RAPPORT D'INCIDENT ===
    
    {corps}
    
    =========================================
    """
    msg.attach(MIMEText(corps_complet, 'plain'))

    try:
        # Connexion au serveur SMTP sur le port sécurisé 465 (SSL/TLS)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EXPEDITEUR, MOT_DE_PASSE)
            server.send_message(msg)
            logging.info(f"Notification '{sujet}' envoyée avec succès à {DESTINATAIRE}")
    except smtplib.SMTPAuthenticationError:
        logging.error("Authentification SMTP refusée. Vérifiez le mot de passe d'application.")
    except Exception as e:
        logging.error(f"Échec de la transmission SMTP : {e}")

# ==========================================
# PLAYBOOKS DE NOTIFICATION (TEMPLATES)
# ==========================================

def alerte_panne_reseau(nom_vm, ip):
    """Template d'alerte pour une perte de connectivité (Ping/Réseau)."""
    sujet = f"⚠️ [INCIDENT RÉSEAU] DRaC : {nom_vm} injoignable"
    corps = (
        f"Alerte de niveau 2 (Infrastructure).\n"
        f"Le serveur {nom_vm} ({ip}) ne répond plus aux requêtes ICMP (Ping).\n\n"
        f"Action automatique : Un signal de démarrage à froid a été envoyé via l'API Proxmox."
    )
    envoyer_mail_formate(sujet, corps)

def alerte_securite_defacage(nom_vm, url):
    """Template d'alerte pour une violation d'intégrité (Piratage/Ransomware)."""
    sujet = f"🚨 [INCIDENT SÉCURITÉ] DRaC : Compromission détectée sur {nom_vm}"
    corps = (
        f"Alerte CRITIQUE de niveau 1 (Sécurité).\n"
        f"Une modification non autorisée a été détectée sur {nom_vm} ({url}). "
        f"L'empreinte cryptographique est invalide (Défaçage ou Chiffrement).\n\n"
        f"Action automatique : Lancement immédiat du Playbook DRaC (Isolement, Preuve, Restauration)."
    )
    envoyer_mail_formate(sujet, corps)

def alerte_securite_bruteforce(nom_vm, ip_attaquant):
    """Template d'alerte pour une tentative d'intrusion par Brute Force SSH."""
    sujet = f"🚨 [DRaC] ALERTE SÉCURITÉ : Brute Force en cours sur {nom_vm}"
    corps = (
        f"Alerte de niveau 1 (Sécurité).\n"
        f"Le serveur {nom_vm} subit actuellement une attaque par force brute sur le port SSH.\n\n"
        f"IP de l'attaquant : {ip_attaquant}\n\n"
        f"Action automatique : Lancement de l'isolement périmétrique (Mise en quarantaine)."
    )
    envoyer_mail_formate(sujet, corps)

def alerte_resolution(nom_vm, ip):
    """Template d'information pour la clôture d'un incident."""
    sujet = f"✅ [RÉSOLUTION] DRaC : {nom_vm} opérationnel"
    corps = (
        f"Clôture d'incident.\n"
        f"L'anomalie détectée sur le serveur {nom_vm} ({ip}) a été traitée avec succès. "
        f"L'intégrité du système a été vérifiée et validée par les sondes de sécurité."
    )
    envoyer_mail_formate(sujet, corps)
