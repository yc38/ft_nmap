# ft_nmap : roadmap

## État actuel

Le projet **ne compile pas encore**. Voici ce qui bloque, à corriger en premier :

| Fichier | Problème |
|---|---|
| `include/ft_nmap.h:42` | `parse_args` utilise `t_options` avant que le `typedef` soit déclaré. Il faut placer le struct avant les prototypes. |
| `src/parsing.c:70` | `require_value` utilise `argv` alors que ce paramètre ne lui est pas passé. |
| `src/parsing.c:128` | `parse_ports` est appelée mais n'existe nulle part. |
| `src/parsing.c:4` | `is_scan_name` n'est jamais utilisée. Avec `-Werror`, ça casse la compilation. |
| `Makefile:7-11` | `parsing.c` est absent de `SRC`, alors que `ft_nmap.h` y est (à retirer). Il n'y a pas de dépendance sur le header, donc le code n'est pas recompilé quand le `.h` change. Ajoute `-MMD -MP` et `-include $(OBJ:.o=.d)`. |
| `src/main.c` | `parse_args` n'est jamais appelée. |

Le reste est bon : libpcap est installé, `/etc/services` est présent, et la logique de parsing tient la route.

---

## Roadmap

Les phases sont dans l'ordre des dépendances. Chacune finit par un critère vérifiable : ne passer à la suivante que quand il est rempli.

### Phase 0 : comprendre la théorie (½ à 1 jour, à ne pas sauter)

**À comprendre :**
- **Les en-têtes IPv4 et TCP, champ par champ** : flags TCP (SYN, ACK, RST, FIN, PSH, URG), ports, seq, checksum. Il faut les construire soi-même.
- **Le checksum TCP/UDP** : il se calcule sur un *pseudo-header* (src IP, dst IP, 0, protocole, longueur) suivi du segment. C'est la source n°1 de paquets ignorés silencieusement.
- **Le byte order** : `htons`/`htonl`/`ntohs`. Tout ce qui part sur le réseau est en big-endian.
- **Les 6 scans et l'interprétation des réponses.** Ce tableau est le cœur du projet :

| Scan | Flags envoyés | Réponse → état |
|---|---|---|
| SYN | SYN | SYN/ACK → **Open** · RST → **Closed** · rien ou ICMP unreachable → **Filtered** |
| NULL | aucun | RST → **Closed** · rien → **Open\|Filtered** · ICMP unreach → **Filtered** |
| FIN | FIN | idem NULL |
| XMAS | FIN+PSH+URG | idem NULL |
| ACK | ACK | RST → **Unfiltered** · rien ou ICMP unreach → **Filtered** |
| UDP | datagramme UDP vide | réponse UDP → **Open** · ICMP type 3 code 3 → **Closed** · autre ICMP type 3 (codes 1,2,9,10,13) → **Filtered** · rien → **Open\|Filtered** |

- **Envoi et réception sont séparés.** On envoie avec un **raw socket** (`socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` ou `IPPROTO_TCP` avec `IP_HDRINCL`). On reçoit avec **pcap**, parce qu'un raw socket ne voit pas proprement les RST et les ICMP qui reviennent.
- **Root obligatoire** : sans root, pas de raw socket. Vérifier `getuid() == 0` au démarrage et afficher une erreur claire si ce n'est pas le cas.

Lecture utile : `man nmap`, section *PORT SCANNING TECHNIQUES*. Elle explique exactement ce tableau.

### Phase 1 : fondations (½ jour)

1. Corriger la compilation (tableau plus haut).
2. Finir le parsing :
   - `parse_ports` : accepter `1-10`, `1,2,3`, `1,5-15`. Rejeter les ports hors de 1-65535 et les plages inversées. Dédoublonner (un tableau `bool seen[65536]` suffit). Erreur si **plus de 1024 ports**. Par défaut : 1-1024.
   - `--file` : lire une cible par ligne, ignorer les lignes vides.
   - Cibles : `inet_pton` pour une IP, sinon `getaddrinfo` pour un hostname/FQDN (fait partie de la libc, donc autorisé).
   - Convention à choisir et à savoir justifier en soutenance : `--speedup 0` signifie que le thread principal fait tout.
3. Afficher le bloc *Scan Configurations*.

**Critère de fin :** `./ft_nmap --ip scanme.nmap.org --ports 1,5-15 --scan SYN,UDP` affiche une config correcte. Toutes les entrées invalides donnent une erreur propre, sans crash (tester aussi avec `valgrind`).

### Phase 2 : un seul paquet SYN, de bout en bout (1 jour, l'étape la plus importante)

Pas encore de threads ni de boucle sur les ports : **1 IP, 1 port, 1 SYN**.

1. **Trouver l'IP source.** Astuce simple : créer un socket UDP, faire `connect()` vers la cible, puis `getsockname()`.
2. **Construire** l'en-tête IP, l'en-tête TCP et le checksum, puis envoyer avec `sendto`.
3. **Capturer avec pcap** : `pcap_open_live` (ou `pcap_create` + `pcap_set_immediate_mode` + `pcap_activate`), puis `pcap_compile`/`pcap_setfilter` avec un filtre du style `src host <cible> and (tcp or icmp)`. Ensuite `pcap_dispatch` avec un timeout, ou `pcap_setnonblock`.
4. **Gérer `pcap_datalink()`** : Ethernet = 14 octets d'en-tête, `any` (DLT_LINUX_SLL) = 16, loopback = 14 sous Linux. Sinon le parsing des paquets sera décalé.
5. Parser la réponse : IP, puis TCP (flags) ou ICMP. Pour un ICMP, l'en-tête IP et TCP d'origine sont inclus dans le message : c'est comme ça qu'on retrouve à quel port il correspond.

**Outils de debug :** `sudo tcpdump -i any -nn port 80` dans un autre terminal, ou Wireshark, qui signale les checksums faux. Pour avoir un port ouvert en local : `nc -lk 4242`.

**Critère de fin :** SYN vers `127.0.0.1:4242` donne Open, port fermé donne Closed, et tcpdump montre un paquet valide.

### Phase 3 : les 6 types de scan (½ à 1 jour)

1. Généraliser l'envoi : une fonction `send_probe(target, port, scan_type)`. Seuls les flags TCP changent, sauf pour UDP qui a son propre en-tête.
2. **Associer chaque réponse à son scan** : donner un **port source différent à chaque type de scan** (par exemple `base + scan_index`). La réponse arrive sur ce port, donc on sait à quel scan elle répond. Le port scanné est le port source de la réponse.
3. **Timeout et retransmission** : un port sans réponse n'est pas forcément filtré, le paquet a pu se perdre. Après l'envoi, attendre environ 1 à 2 s, renvoyer une fois les sondes sans réponse, puis appliquer les états « pas de réponse » du tableau.
4. Stocker les résultats dans un tableau `result[target][port_index][scan]`.

**Critère de fin :** pour chaque scan, les résultats sur `127.0.0.1` et `scanme.nmap.org` (cible autorisée par nmap.org) sont cohérents avec un vrai `sudo nmap -sS / -sN / -sF / -sX / -sA / -sU` lancé à la main. On a le droit de *comparer* avec nmap, pas de l'appeler depuis le programme. Pour obtenir des ports filtrés : `sudo iptables -A INPUT -p tcp --dport 4243 -j DROP`.

### Phase 4 : threads (1 jour)

**À comprendre :** `pthread_create`/`join`, `pthread_mutex`, les data races. Tester avec `-fsanitize=thread` ou `valgrind --tool=helgrind`.

Architecture simple et défendable :
- **Une file de jobs** (cible, port, scan) protégée par un mutex.
- **N threads d'envoi** (`--speedup`) qui piochent dans la file.
- **Un thread de capture pcap** qui lit les réponses et remplit le tableau de résultats (sous mutex).
- Fin de scan : quand la file est vide et que le dernier timeout est écoulé, `pcap_breakloop` arrête la capture, puis `join` sur tous les threads.

**Critère de fin :** `--speedup 0`, `--speedup 50` et `--speedup 250` donnent **les mêmes résultats**, et le temps baisse quand le nombre de threads augmente. Aucun warning TSan.

### Phase 5 : sortie et conclusion (½ jour)

1. Nom du service avec `getservbyport(htons(port), "tcp"/"udp")`, ou `"Unassigned"` s'il n'existe pas.
2. **Conclusion par port**, avec une règle cohérente avec les exemples du sujet : Open si un scan dit Open, sinon Closed si un scan dit Closed, sinon Filtered, Unfiltered ou Open|Filtered.
3. Deux sections, *Open ports* et *Closed/Filtered/Unfiltered ports*, en colonnes alignées.
4. Le temps total avec `clock_gettime(CLOCK_MONOTONIC)` (« Scan took X secs »), et des points de progression pendant le scan.
5. Un bloc de résultats par IP en mode `--file`.

### Phase 6 : solidité avant la soutenance (½ jour)

- Tests d'erreurs : pas root, IP invalide, hostname introuvable, fichier inexistant ou vide, 1025 ports, `--speedup 251` ou `-1` ou `abc`, option sans valeur, `--ip` et `--file` ensemble.
- `valgrind --leak-check=full` : 0 leak, 0 erreur. Penser à `pcap_close`, `pcap_freecode`, `freeaddrinfo`, `close(socket)`.
- Gérer SIGINT proprement (Ctrl+C pendant un scan), en bonus de robustesse.
- Makefile : `make` lancé deux fois ne recompile rien, et modifier le `.h` déclenche bien une recompilation.
- Une VM Debian avec un noyau > 3.14 : la Debian 13 (6.12) convient.

### Bonus (seulement si la partie obligatoire est parfaite)

Le sujet est strict là-dessus. Les bonus les plus rentables sont la **source IP spoofée / decoy** (l'en-tête IP est déjà construit à la main, c'est presque gratuit) et des options comme `--timeout` ou `--ttl`. L'OS detection est longue à faire.

---

**Ordre de priorité en cas de manque de temps :** la phase 2 conditionne tout. Tant qu'un seul SYN ne revient pas correctement, ne pas ajouter les autres scans ni les threads.
