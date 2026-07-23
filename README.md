# 🛡️ DRaC-Project (Dynamic Recovery and Containment)

> **Orchestrateur de sécurité (SOAR) Out-of-Band avec auto-réparation pour Proxmox VE, couplé à Wazuh (HIDS) et SLIPS (NIDS/IA).**

**DRaC** est un Proof of Concept (PoC) d'orchestrateur de sécurité développé en Python dans le cadre d'un mémoire de fin de formation (Licence en Sécurité Informatique - IFRI / UAC). Il a été conçu spécifiquement pour répondre aux exigences de haute disponibilité de l'infrastructure de l'entreprise 3DTechlogis.

---

## 📖 Présentation

Face aux limites des outils de supervision passifs et des réponses locales (In-Band) qui peuvent être désactivées par un attaquant, DRaC propose une **architecture de défense Out-of-Band**. 

Hébergé sur une machine de management isolée, il écoute les alertes provenant de moteurs de détection avancés et interagit directement avec l'API de l'hyperviseur physique (Proxmox VE) pour confiner la cible ou réparer les dégâts de manière autonome et instantanée (MTTR < 2 secondes).

---

## 🏗️ Architecture Hybride

Le projet repose sur la synergie de trois composants majeurs :
*   **Wazuh (HIDS / SIEM) :** Surveillance interne de la cible, contrôle d'intégrité des fichiers (FIM) et détection des abus de privilèges.
*   **SLIPS (NIDS / IA) :** Analyse réseau comportementale par Machine Learning (via Port Mirroring) pour détecter les scans furtifs et les communications de malwares (C2).
*   **DRaC (SOAR) :** L'orchestrateur central, cerveau décisionnel et bras armé du système.

---

## ⚙️ Modules Python (Code Source)

Ce dépôt contient les scripts centraux de l'orchestrateur, conçus selon une approche microservices :

*   `main.py` : Le service proactif qui vérifie en boucle la santé réseau, applicative et l'intégrité (Hash SHA-256) de la cible.
*   `webhook_drac.py` : L'API Flask réactive (port TCP/5000) qui ingère et filtre les alertes JSON qualifiées.
*   `custom-slips.py` : Le pont de traduction asynchrone qui intercepte en temps réel les découvertes de l'Intelligence Artificielle.
*   `detector.py` : Bibliothèque de sondages actifs (ICMP, TCP, requêtes HTTP).
*   `reactor.py` : Le cœur de l'automatisation. Contient les Playbooks d'interaction avec l'API Proxmox (Confinement réseau, Firewall DROP, Capture forensique, Rollback de snapshots).
*   `notifier.py` : Module de reporting générant les alertes SMTP formatées.
*   `mode_maintenance.py` : Script de gestion des faux positifs permettant la suspension sécurisée des boucliers lors des opérations légitimes de mise à jour.

---

## ⚠️ Avertissement

Ce code a été développé à des fins académiques et de démonstration sur un environnement virtualisé fermé. Le déploiement en production nécessite un durcissement supplémentaire de l'infrastructure (chiffrement TLS de l'API Flask, utilisation d'un gestionnaire de secrets type HashiCorp Vault, et durcissement des conteneurs Docker).
