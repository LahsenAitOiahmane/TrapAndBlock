# Rapport Technique AutoTableV2 (Markdown)

## Objet
Rapport détaillé et structuré du script `AutoTableV2.sh` (exclusivement), avec sections claires, explications, et emplacements de captures.

## Sommaire
1. Préambule et directives de sécurité
2. Variables réseau et constantes
3. Fonctions utilitaires
4. Préparation système
5. Configuration réseau
6. Réinitialisation et Honeypot
7. Règles de base et Anti-spoofing
8. Sécurité avancée: Hard Ban unifié
9. Règles de service
10. Journalisation finale
11. Persistance des règles
12. Orchestration (main)
13. Captures d’écran (preuves)

## 1. Préambule et directives de sécurité
- `set -e`: arrêt en cas d’erreur
- `set -u`: arrêt en cas de variable non définie
- `set -o pipefail`: sécurité des pipes
- `readonly`: constants pour interfaces/IP

## 2. Variables réseau et constantes
- Interfaces: `enp0s3`, `enp0s8`
- IPs/Passerelle: définies selon topologie
- Réseau autorisé: utilisé par anti-spoofing et ping

## 3. Fonctions utilitaires
- `info(msg)`: log info via `logger -t`
- `warn(msg)`: log alerte via `logger -t`
- `require_root()`: vérifie utilisateurs root

## 4. Préparation système
- Installe: `iptables`, `iptables-persistent`, `rsyslog`, `iproute2`
- Active rsyslog: `systemctl restart/enable rsyslog`

## 5. Configuration réseau
- `ip addr replace`, `ip link set up`
- `ip route replace default via <gw>`

## 6. Réinitialisation et Honeypot
- Flush: `iptables -w -F`, `-X`
- Politiques: `INPUT/FORWARD DROP`, `OUTPUT ACCEPT`
- Chaînes: `HONEYPOT_INPUT`, `HONEYPOT_FORWARD` → `LOG` avec préfixes + `DROP`

## 7. Règles de base et Anti-spoofing
- Loopback: `-i lo -j ACCEPT`
- Conntrack: `--ctstate ESTABLISHED,RELATED -j ACCEPT`
- Invalides: `--ctstate INVALID -j HONEYPOT_INPUT`
- Anti-spoofing: chaîne avec `-s <réseau> -j RETURN`, sinon `LOG` + `DROP`

## 8. Sécurité avancée: Hard Ban unifié
- Listes `recent`: `ABUSE_COUNT`, `ABUSE_BANNED`
- Ports protégés (multiport): `21,22,23`
- Règle bannis: `--name ABUSE_BANNED --update --seconds 60 -j DROP`
- Compteur: `--name ABUSE_COUNT --set`
- Seuil: `--rcheck --hitcount 4 --seconds 60` → log + ban
- Préfixes: `FTP_HARD_BAN:`, `SSH_HARD_BAN:`, `TELNET_HARD_BAN:`

## 9. Règles de service
- Ping interne autorisé, HTTP si requis
- Philosophie: honeypot pour le reste

## 10. Journalisation finale
- `drop_logging`: envoie vers `HONEYPOT_*` puis `DROP`
- SYN flood: `--limit 1/s --limit-burst 4` → surplus honeypot

## 11. Persistance des règles
- `iptables-save > /etc/iptables/rules.v4`
- `netfilter-persistent save`

## 12. Orchestration (main)
1. `require_root`, deps, interfaces, routes, rsyslog
2. flush, honeypot
3. base, anti-spoofing
4. hard ban
5. services
6. drop logging
7. persistance

## 13. Captures d’écran (preuves)
- `CAPTURE_IPTABLES_LISTING.png`: sortie `iptables -L -v -n` (chaînes honeypot, compteurs)
- `CAPTURE_SYSLOG_HONEYPOT.png`: `/var/log/syslog` avec `HONEYPOT_ATTACK_*` lors de scans
- `CAPTURE_HARD_BAN_SSH.png`: `SSH_HARD_BAN:` et `cat /proc/net/xt_recent/ABUSE_BANNED`
- `CAPTURE_SYN_FLOOD.png`: logs `HONEYPOT_ATTACK_INPUT:` pendant `hping3 --flood`
- `CAPTURE_RULES_V4.png`: extrait de `/etc/iptables/rules.v4` après `iptables-save`
