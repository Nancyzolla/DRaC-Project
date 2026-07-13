# DRaC-Project
DRaC (Dynamic Recovery and Containment) : Orchestrateur de sécurité (SOAR) Out-of-Band avec auto-réparation pour Proxmox VE, couplé à Wazuh (HIDS) et SLIPS (NIDS/IA).
# DRaC : Dynamic Recovery and Containment

**DRaC** est un Proof of Concept (PoC) d'orchestrateur de sécurité (SOAR) développé en Python dans le cadre d'un mémoire de fin de formation (Licence en Sécurité Informatique - IFRI / UAC). Il a été conçu pour l'infrastructure de l'entreprise 3DTechlogis.

## 📖 Présentation
Face aux limites des outils de supervision passifs et des réponses locales (In-Band), DRaC propose une architecture de défense **Out-of-Band**. Hébergé sur une machine de management isolée, il écoute les alertes provenant de moteurs de détection avancés et interagit directement avec l'API de l'hyperviseur physique (**Proxmox VE**) pour confiner la cible ou réparer les dégâts de manière autonome.

## 🏗️ Architecture Hybride
Le projet repose sur la synergie de trois composants :
1. **Wazuh (HIDS / SIEM) :** Surveillance interne, contrôle d'intégrité (FIM) et détection des abus de privilèges.
2. **SLIPS (NIDS / IA) :** Analyse réseau comportementale par Machine Learning (via Port Mirroring) pour détecter les scans furtifs et attaques C2.
3. **DRaC (SOAR) :** Le cerveau décisionnel et bras armé du système.

## ⚙️ Modules Python (Code Source)
Ce dépôt contient les scripts centraux de l'orchestrateur :
* `main.py` : Le service proactif qui vérifie en boucle la santé et l'intégrité (Hash SHA-256) de la cible.
* `webhook_drac.py` : L'API Flask réactive (port TCP/5000) qui ingère les alertes JSON qualifiées.
* `detector.py` : Bibliothèque de sondages actifs (ICMP, TCP, HTTP).
* `reactor.py` : Le cœur de l'automatisation. Contient les Playbooks d'interaction avec l'API Proxmox (Confinement réseau, Firewall DROP, Rollback de snapshots).
* `notifier.py` : Module de reporting générant les alertes SMTP.
* `mode_maintenance.py` : Script de gestion des faux positifs pour les opérations légitimes.

## ⚠️ Avertissement
*Ce code a été développé à des fins académiques et de démonstration sur un environnement virtualisé fermé. Le déploiement en production nécessite un durcissement supplémentaire (chiffrement TLS de l'API Flask, gestionnaire de secrets).*
