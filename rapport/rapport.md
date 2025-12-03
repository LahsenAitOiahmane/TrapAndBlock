2. Mise en place de Iptables : Script et Explication
Pour automatiser et standardiser la sécurisation de notre serveur Linux, nous avons développé le script AutoTableV2. Ce chapitre détaille le fonctionnement interne du script et analyse les commandes système et réseau exécutées.
2.1. Initialisation et Sécurité du Script
Dès le début du script, nous définissons des directives pour assurer une exécution sûre et des variables immuables pour l'environnement réseau.
 
Analyse des commandes :
Commande / Option	Explication Technique
set -e	Arrête immédiatement le script si une commande retourne une erreur (code de sortie non nul).
set -u	Arrête le script si on tente d'utiliser une variable non définie (évite les commandes vides dangereuses).
set -o pipefail	Si une commande échoue dans un "pipe" (`
readonly	Déclare des constantes (Interface, IP, Réseau). Le script ne peut pas les modifier par erreur plus loin.
logger -t	Utilisé dans nos fonctions info() et warn(). Envoie les messages du script vers le journal système (syslog), permettant un audit ultérieur.

2.2. Configuration Réseau et Système
Avant d'appliquer le pare-feu, le script s'assure que l'environnement réseau est correctement configuré via la suite iproute2 et systemd.
   
Analyse des commandes :
Commande	Explication Technique
ip addr replace ...	Assigne l'adresse IP définie à l'interface. L'option replace met à jour l'IP si elle existe déjà ou l'ajoute.
ip link set ... up	Active électriquement et logiquement l'interface réseau.
ip route replace default	Définit la passerelle par défaut pour l'accès Internet.
systemctl restart/enable	Redémarre le service de journalisation rsyslog et l'active au démarrage pour garantir que nos logs Iptables seront bien capturés.

2.3. Réinitialisation et Chaînes Personnalisées
La première action du pare-feu est de nettoyer l'existant et de créer notre infrastructure de journalisation (Honeypot).
  



Analyse des commandes Iptables :
Option Iptables	Signification
-w	Wait : Attend que le verrou xtables soit libéré. Indispensable dans un script pour éviter les erreurs de concurrence.
-F (Flush)	Supprime toutes les règles existantes dans une table donnée.
-X	Supprime les chaînes personnalisées (nettoyage complet).
-P INPUT DROP	Policy : Définit la politique par défaut sur "Refuser". Tout ce qui n'est pas explicitement autorisé sera bloqué.
-N HONEYPOT_INPUT	New Chain : Crée une nouvelle "boîte" pour organiser nos règles de pot de miel.
-j LOG	Jump Log : Envoie le paquet vers le système de logs du noyau.
--log-prefix	Ajoute une étiquette (ex: "HONEYPOT_ATTACK: ") au log pour le retrouver facilement avec grep.
2.4. Règles de Base et Anti-Spoofing
Nous sécurisons les fondations en utilisant le module conntrack pour le suivi d'état et en filtrant les adresses sources.
 
Analyse des commandes :
Commande / Module	Explication Technique
-i lo -j ACCEPT	Autorise tout le trafic sur l'interface de boucle locale (vital pour les processus système).
-m conntrack	Charge le module de suivi de connexion (Stateful Inspection).
--ctstate ESTABLISHED	Autorise les paquets appartenant à une connexion déjà validée (évite de revérifier chaque paquet).
--ctstate INVALID	Bloque les paquets qui ne respectent pas les standards TCP/IP (souvent des scans ou erreurs).
-s $NETWORK -j RETURN	Dans la chaîne anti-spoofing : si l'IP source est légitime, on quitte la chaîne et on continue l'analyse.

2.5. Sécurité Avancée : Hard Ban Unifié (Modules Recent & Multiport)
Cette partie contient la logique la plus complexe, utilisant des modules avancés pour créer le bannissement temporaire sur plusieurs ports simultanément.
   
Analyse des commandes expertes :
Commande / Option	Rôle dans le "Hard Ban"
-m multiport	Permet de spécifier plusieurs ports (--dports 21,22,23) dans une seule règle, unifiant la protection.
-m recent	Active le module permettant de créer des listes d'IP dynamiques en mémoire.
--name ABUSE_BANNED	Définit le nom de la liste utilisée comme "Prison".
--update --seconds 60	Vérifie si l'IP est dans la liste. Si oui, met à jour son horodatage (reset du timer) et retourne "Vrai" (déclenchant le -j DROP).
--set	Ajoute l'IP source à la liste surveillée.
--rcheck	Vérifie simplement si l'IP est dans la liste sans mettre à jour le timer.
--hitcount 4	Condition : "Si l'IP a été vue 4 fois ou plus".

2.6. Persistance des Règles
Enfin, le script assure que la configuration survit au redémarrage de la machine.
 
Analyse des commandes :
Commande	Explication Technique
iptables-save	Affiche la configuration actuelle du noyau (règles actives) sous forme de texte.
RAPPORT TECHNIQUE – AutoTableV2 (Uniquement)

Objet
Ce document décrit, en français et de manière opérationnelle, le fonctionnement du script AutoTableV2. Il n’inclut aucun autre script ou fichier. Le style est volontairement “direct” (sans mise en forme Markdown) afin d’être utilisé tel quel dans des environnements de documentation technique interne.

Portée
• Machine cible : LinuxServer
• Script unique : AutoTableV2.sh
• Composants couverts : variables, fonctions, options, commandes système, iptables, persistance, ordre d’exécution

Plan général
1. Préambule et directives de sécurité d’exécution
2. Variables réseau et constantes
3. Fonctions utilitaires (log/info/warn)
4. Préparation système (dépendances, rsyslog)
5. Configuration réseau (interfaces, routes)
6. Réinitialisation pare-feu et chaînes honeypot
7. Règles de base et anti-spoofing
8. Sécurité avancée : Hard Ban unifié (modules recent et multiport)
9. Règles de service (accès légitime)
10. Journalisation et capture finale (drop + logs)
11. Persistance des règles
12. Orchestration (main) et ordre d’application
13. Emplacements des captures d’écran (preuves)

1. Préambule et directives de sécurité d’exécution
• set -e : arrête le script immédiatement si une commande retourne un code d’erreur.
• set -u : arrête si une variable non définie est utilisée (sécurité des expansions).
• set -o pipefail : enchaînement de commandes “|” sûr; un échec dans une sous-commande fait échouer l’ensemble.
• readonly : déclare des constantes (interfaces, IP, réseaux) pour éviter toute modification accidentelle.

2. Variables réseau et constantes
• Interface WAN/LAN : noms d’interface utilisés par le script (ex. enp0s3, enp0s8). Déclarées en readonly.
• Adresses IP : IP de LinuxServer pour DMZ/LAN, passerelle par défaut. Déclarées en readonly.
• Réseaux autorisés : sous-réseau interne utilisé par les règles (anti-spoofing, ping autorisé). Déclaré en readonly.

3. Fonctions utilitaires
• info(message) : envoie un message d’information au syslog via “logger -t”.
• warn(message) : envoie un message d’alerte au syslog via “logger -t”.
• require_root() : vérifie que l’utilisateur effectuant l’exécution est root, sinon stoppe.

4. Préparation système
• install_dependencies() : installe iptables, iptables-persistent, rsyslog, iproute2 si absents.
• configure_rsyslog() : redémarre et active rsyslog pour garantir la capture des logs kernel et firewall.

5. Configuration réseau
• configure_interfaces() : applique les IP sur les interfaces via “ip addr replace …”, puis “ip link set … up”.
• configure_routes() : positionne la route par défaut via “ip route replace default via GATEWAY”.

6. Réinitialisation pare-feu et chaînes honeypot
• flush_tables() : iptables -w -F (flush), -X (supprime les chaînes perso), -P INPUT/FORWARD DROP, -P OUTPUT ACCEPT.
• honeypot_chains() : crée les chaînes HONEYPOT_INPUT et HONEYPOT_FORWARD. Chaque chaîne : -j LOG avec préfixe (HONEYPOT_ATTACK_*), puis -j DROP.
• Objectif : capturer les scans, trafics non autorisés, excédents DoS avant le DROP, avec une trace exploitable.

7. Règles de base et anti-spoofing
• base_rules() :
	- Autorise loopback : “-i lo -j ACCEPT”.
	- Suivi d’état : “-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT”.
	- Élimine invalides : “-m conntrack --ctstate INVALID -j HONEYPOT_INPUT”.
• anti_spoofing_chain() : chaîne qui vérifie “-s RESEAU_AUTORISE -j RETURN”, sinon LOG + DROP.

8. Sécurité avancée : Hard Ban unifié
• Principe : utiliser “-m recent” pour deux listes mémoire:
	- ABUSE_COUNT : liste de suivi des nouvelles tentatives (NEW) sur ports sensibles.
	- ABUSE_BANNED : liste de bannis pendant 60 secondes.
• Ports protégés : 21 (FTP), 22 (SSH), 23 (Telnet), définis via “-m multiport --dports 21,22,23”.
• Règle 1 : si source est dans ABUSE_BANNED → “-m recent --name ABUSE_BANNED --update --seconds 60 -j DROP”. Conséquence : timer remis à zéro à chaque tentative, bannissement effectif 60s glissants.
• Règle 2 : enregistre toute tentative NEW → “-m recent --name ABUSE_COUNT --set”.
• Règle 3 : si “--rcheck --name ABUSE_COUNT --hitcount 4 --seconds 60” alors LOG avec préfixe par service et envoie vers ajout bannis, puis DROP.
• Journaux : préfixes spécifiques “FTP_HARD_BAN:”, “SSH_HARD_BAN:”, “TELNET_HARD_BAN:”.
• Ordonnancement : ces règles sont évaluées avant toute ACCEPT de service (priorité réputation).

9. Règles de service
• service_rules() : autorise les services légitimes (ex. HTTP, ICMP local autorisé), tout en maintenant la philosophie honeypot sur services non déclarés.
• Exemple d’autorisation : Ping depuis le réseau interne; HTTP ouvert si besoin de test web.

10. Journalisation et capture finale
• drop_logging() : toutes les autres correspondances sont dirigées vers HONEYPOT_INPUT/HONEYPOT_FORWARD pour LOG + DROP.
• SYN flood : chaîne dédiée limite “--limit 1/s --limit-burst 4”, l’excédent bascule vers HONEYPOT_INPUT.

11. Persistance des règles
• persist_rules() : “iptables-save > /etc/iptables/rules.v4” puis “netfilter-persistent save” pour garantir restauration au boot.

12. Orchestration (main)
• Ordre critique :
	1/ require_root, install_dependencies, configure_interfaces, configure_routes, configure_rsyslog
	2/ flush_tables, honeypot_chains
	3/ base_rules, anti_spoofing_chain
	4/ advanced_security (Hard Ban unifié)
	5/ service_rules
	6/ drop_logging
	7/ persist_rules
• Justification : la réputation (Hard Ban) doit précéder l’analyse d’accès; l’hygiène (invalides/spoof) avant tout; les services légitimes sont examinés après ces filtres; la journalisation finale clôture ce qui reste.

13. Emplacements des captures d’écran (preuves)
• Capture 1 – iptables -L -v -n : preuve du chargement des chaînes HONEYPOT_* et des compteurs, à insérer après exécution initiale (emplacement: CAPTURE_IPTABLES_LISTING.png).
• Capture 2 – /var/log/syslog : lignes HONEYPOT_ATTACK_* lors d’un scan Nmap, filtre SMTP ou SNMP; grep sur le préfixe (emplacement: CAPTURE_SYSLOG_HONEYPOT.png).
• Capture 3 – SSH_HARD_BAN: : montrer la ligne de ban avec IN=, SRC=, DPT=22 lors d’un hydra; inclure aussi “cat /proc/net/xt_recent/ABUSE_BANNED” (emplacement: CAPTURE_HARD_BAN_SSH.png).
• Capture 4 – SYN flood : exécuter hping3 et montrer le LOG “HONEYPOT_ATTACK_INPUT:” avec timestamps et compteur (emplacement: CAPTURE_SYN_FLOOD.png).
• Capture 5 – Persistance : afficher “/etc/iptables/rules.v4” après “iptables-save” (emplacement: CAPTURE_RULES_V4.png).

Annexe – Références d’options iptables utilisées
• -w : attente du verrou xtables, recommandé en scripts concurrents.
• -F/-X : flush et suppression des chaînes personnalisées.
• -P CHAIN POLICY : définit la politique par défaut (DROP/ACCEPT).
• -N CHAIN : crée une nouvelle chaîne utilisateur.
• -A/-I : ajoute/insère une règle dans une chaîne.
• -j TARGET : saute vers une cible (ACCEPT, DROP, LOG, chaîne)
• -m conntrack --ctstate … : inspection d’état (ESTABLISHED, RELATED, INVALID).
• -m limit : contrôle de taux pour SYN flood.
• -m multiport --dports … : groupement de ports.
• -m recent --name LIST --set/--rcheck/--update --hitcount N --seconds S : listes dynamiques et condition de bannissement.

Fin du rapport AutoTableV2 (uniquement).
2.	L'Identité (SRC=192.168.1.145) : L'adresse IP de l'attaquant est clairement identifiée.

3.	La Cible (DPT=22) : Confirme que l'attaque visait le port SSH.
