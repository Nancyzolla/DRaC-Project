#!/usr/bin/env python3
"""
Module de Réaction Automatisée (DRaC - Dynamic Recovery and Containment).
Gère l'isolation réseau, la capture forensique, la restauration et les alertes.
"""

import os
import paramiko
import time
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from proxmoxer import ProxmoxAPI
from dotenv import load_dotenv
import urllib3

# Désactivation des alertes SSL pour l'API Proxmox
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Chargement du coffre-fort des secrets
load_dotenv()

# --- CONFIGURATION GLOBALE ---
PROXMOX_HOST = os.getenv("PROXMOX_HOST")
PROXMOX_USER = os.getenv("PROXMOX_USER")
PROXMOX_TOKEN_NAME = os.getenv("PROXMOX_TOKEN_NAME")
PROXMOX_TOKEN_VALUE = os.getenv("PROXMOX_TOKEN_VALUE")

MAIL_USER = os.getenv("MAIL_USER")
MAIL_PASS = os.getenv("MAIL_PASS")
MAIL_DEST = os.getenv("MAIL_DEST")

# Configuration standardisée des journaux (Logs)
logging.basicConfig(
    filename='/var/log/drac_reactor.log',
    level=logging.INFO,
    format='%(asctime)s - [DRaC-SOC] - %(levelname)s - %(message)s'
)

def envoyer_alerte_email(sujet, corps):
    """Envoie un rapport d'incident standardisé par email."""
    if not MAIL_USER or not MAIL_PASS:
        logging.warning("Configuration email manquante dans le .env.")
        return

    msg = MIMEMultipart()
    msg['From'] = f"DRaC Security <{MAIL_USER}>"
    msg['To'] = MAIL_DEST
    msg['Subject'] = f"[CRITICAL] DRaC Alert - {sujet}"

    # Formatage professionnel du corps du mail
    corps_pro = f"""
    === SYSTÈME DE DÉFENSE DRaC ===
    Date de l'événement : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    
    DÉTAILS DE L'INTERVENTION :
    {corps}
    
    Statut : Traité automatiquement par l'agent DRaC.
    =================================
    """
    msg.attach(MIMEText(corps_pro, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(MAIL_USER, MAIL_PASS)
        server.send_message(msg)
        server.quit()
        logging.info("Rapport d'incident envoyé par email avec succès.")
    except Exception as e:
        logging.error(f"Échec de l'envoi de l'email d'alerte : {e}")

def connecter_proxmox():
    """Établit une session sécurisée avec l'hyperviseur Proxmox."""
    try:
        return ProxmoxAPI(
            PROXMOX_HOST,
            user=PROXMOX_USER,
            token_name=PROXMOX_TOKEN_NAME,
            token_value=PROXMOX_TOKEN_VALUE,
            verify_ssl=False
        )
    except Exception as e:
        logging.error(f"Échec critique de connexion Proxmox : {e}")
        return None

def isoler_reseau_vm(noeud, vmid, nom_vm):
    """Confinement immédiat : Déconnexion virtuelle de l'interface réseau."""
    proxmox = connecter_proxmox()
    if not proxmox: return False

    try:
        config = proxmox.nodes(noeud).qemu(vmid).config.get()
        net0 = config.get('net0')

        if net0 and 'link_down=1' not in net0:
            logging.warning(f"[{nom_vm}] ISOLATION RÉSEAU : Câble virtuel déconnecté.")
            proxmox.nodes(noeud).qemu(vmid).config.put(net0=f"{net0},link_down=1")
        else:
            logging.info(f"[{nom_vm}] La machine est déjà isolée du réseau.")
        return True
    except Exception as e:
        logging.error(f"Échec de l'isolation réseau sur {nom_vm} : {e}")
        return False

def sauvegarder_scene_crime(noeud, vmid, nom_vm):
    """Capture forensique de l'état des disques pour enquête ultérieure."""
    proxmox = connecter_proxmox()
    if not proxmox: return False

    nom_preuve = "PREUVE_" + datetime.now().strftime("%Y%m%d_%Hh%Mm%Ss")
    try:
        logging.info(f"[{nom_vm}] Création de l'empreinte forensique : {nom_preuve}")
        proxmox.nodes(noeud).qemu(vmid).snapshot.post(
            snapname=nom_preuve,
            description="[AUTO-DRAC] Capture suite à incident de sécurité",
            vmstate=0
        )
        time.sleep(10)
        return True
    except Exception as e:
        logging.error(f"Échec de la capture de preuve sur {nom_vm} : {e}")
        return False

def restaurer_snapshot(noeud, vmid, nom_vm, snapshot_nom="REF_SAIN"):
    """Playbook SOC Complet : Isolation -> Preuve -> Rollback -> Rétablissement."""
    proxmox = connecter_proxmox()
    if not proxmox: return False

    try:
        envoyer_alerte_email(
            sujet=f"Compromission détectée sur {nom_vm}",
            corps=f"Le serveur {nom_vm} (ID: {vmid}) a subi une altération critique.\nLancement du Playbook de remédiation automatique (DRaC)."
        )

        isoler_reseau_vm(noeud, vmid, nom_vm)
        
        sauvegarder_scene_crime(noeud, vmid, nom_vm)
        time.sleep(8) # Temporisation requise par l'hyperviseur

        logging.warning(f"[{nom_vm}] Lancement du Rollback vers la référence saine : {snapshot_nom}...")
        proxmox.nodes(noeud).qemu(vmid).snapshot(snapshot_nom).rollback.post()
        time.sleep(5)

        config = proxmox.nodes(noeud).qemu(vmid).config.get()
        net0 = config.get('net0', '').replace(',link_down=1', '')
        proxmox.nodes(noeud).qemu(vmid).config.put(net0=net0)
        
        proxmox.nodes(noeud).qemu(vmid).status.start.post()
        
        msg_succes = f"Restauration terminée pour {nom_vm}. La machine est de retour en production."
        logging.info(f"[{nom_vm}] {msg_succes}")
        envoyer_alerte_email("Remédiation réussie", msg_succes)
        
        return True
    except Exception as e:
        logging.error(f"Échec critique du playbook de remédiation : {e}")
        return False

def demarrer_vm(noeud, vmid, nom_vm):
    """Force l'amorçage électrique d'une VM."""
    proxmox = connecter_proxmox()
    if not proxmox: return False
    try:
        logging.info(f"[{nom_vm}] Transmission de l'ordre d'allumage...")
        proxmox.nodes(noeud).qemu(vmid).status.start.post()
        return True
    except Exception as e:
        logging.error(f"Échec de l'allumage pour {nom_vm} : {e}")
        return False

def remedier_douce_ssh(ip_cible, utilisateur="drac_user"):
    """Tentative de remédiation de niveau 1 : Redémarrage des services web via SSH."""
    logging.info(f"[{ip_cible}] Lancement de la remédiation douce (Niveau 1)...")
    path_key = "/home/vm-ms-service/.ssh/id_rsa_drac"

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key = paramiko.RSAKey.from_private_key_file(path_key)
        
        ssh.connect(hostname=ip_cible, username=utilisateur, pkey=key, timeout=10)
        commande = "sudo systemctl restart nginx"
        
        logging.info(f"[{ip_cible}] Exécution distante : {commande}")
        stdin, stdout, stderr = ssh.exec_command(commande)
        exit_status = stdout.channel.recv_exit_status()
        ssh.close()

        if exit_status == 0:
            logging.info(f"[{ip_cible}] Remédiation douce réussie. Service rétabli.")
            return True
        else:
            logging.error(f"[{ip_cible}] Échec de la commande SSH (Code retour: {exit_status}).")
            return False
    except Exception as e:
        logging.error(f"[{ip_cible}] Erreur de communication SSH : {e}")
        return False

def creer_nouveau_snapshot(noeud, vmid, nom_snapshot="REF_SAIN"):
    """Gestion de la maintenance : Renouvellement de la base saine de référence."""
    proxmox = connecter_proxmox()
    if not proxmox: return False

    try:
        logging.info(f"[MAINTENANCE] Purge de l'ancienne référence {nom_snapshot}...")
        try:
            proxmox.nodes(noeud).qemu(vmid).snapshot(nom_snapshot).delete()
            time.sleep(5)
        except Exception:
            pass 

        logging.info(f"[MAINTENANCE] Création de la nouvelle empreinte saine {nom_snapshot}...")
        proxmox.nodes(noeud).qemu(vmid).snapshot.post(
            snapname=nom_snapshot,
            description="[AUTO-MAINTENANCE] Snapshot validé après mise à jour"
        )
        time.sleep(10)
        return True
    except Exception as e:
        logging.error(f"[MAINTENANCE] Échec lors de la création de la référence : {e}")
        return False

def bloquer_ip_via_proxmox(ip_attaquant, vmid="102", noeud="PrxMx-SRV"):
    """Confinement périmétrique : Injection d'une règle DROP dans le pare-feu hyperviseur."""
    logging.info(f"[FIREWALL] Demande de blocage réseau pour l'IP hostile : {ip_attaquant}")
    proxmox = connecter_proxmox()
    if not proxmox: return False

    try:
        proxmox.nodes(noeud).qemu(vmid).firewall.rules.post(
            type="in",
            action="DROP",
            source=ip_attaquant,
            enable=1,
            comment="Bannissement automatique DRaC"
        )
        logging.info(f"[FIREWALL] Règle DROP activée avec succès pour {ip_attaquant} sur la VM {vmid}.")
        return True
    except Exception as e:
        logging.error(f"Échec de l'injection de la règle pare-feu pour {ip_attaquant} : {e}")
        return False
