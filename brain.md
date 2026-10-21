# brain : les explications du prof

> [avant brain] : tout ce qui a été expliqué avant le 2026-10-20 (phases 0 et 1,
> roadmap.md) n'est pas encore recopié ici. À compléter ce soir.
> À partir d'ici, chaque explication est ajoutée à la suite.

---

## Phase 2, étape 1 : trouver l'IP source

### Le problème

Quand on fabrique un paquet IP à la main (raw socket + `IP_HDRINCL`), c'est
**nous** qui remplissons l'en-tête IP, donc le champ `saddr` (adresse source).
Le noyau ne le fera pas à notre place. Or cette adresse doit être juste :

- La cible répond **à l'adresse source écrite dans le paquet**. Si on met une
  mauvaise IP, la réponse (SYN/ACK, RST...) part ailleurs et on ne la voit jamais.
- Le **checksum TCP** inclut un pseudo-header qui contient l'IP source. Une
  mauvaise IP donne donc un checksum faux, et la cible jette le paquet sans rien dire.

Le piège : une machine a souvent **plusieurs IP** (loopback `127.0.0.1`, Wi-Fi,
Ethernet, VPN, Docker...). Laquelle choisir ? Ça dépend de **la destination** :
pour joindre `127.0.0.1` on a `127.0.0.1` comme source, pour joindre
`45.33.32.156` (scanme) on a l'IP de la carte qui sort vers Internet.

### L'astuce : demander au noyau

Le noyau sait déjà faire ce choix avec sa **table de routage** (`ip route`).
On lui pose la question sans envoyer aucun paquet :

1. `socket(AF_INET, SOCK_DGRAM, 0)` : un socket UDP normal, pas besoin d'être root.
2. `connect(fd, cible)` : sur un socket **UDP**, `connect` n'envoie *rien*. UDP n'a
   pas de connexion, donc le noyau note juste « ce socket parle à cette adresse »
   et **choisit la route et l'IP locale** qui vont avec.
3. `getsockname(fd, &local, &len)` : renvoie l'adresse locale du socket, c'est-à-dire
   l'IP source choisie par le noyau.
4. `close(fd)`.

(Avec un socket TCP, `connect` ferait vraiment le handshake. C'est pour ça qu'on
prend UDP.)

### Détails du code (`src/source_ip.c`)

- Le port utilisé dans `connect` (53) n'a aucune importance : rien n'est envoyé.
  Il faut juste un port valide.
- `htons(53)` : le port est mis en **ordre réseau** (big-endian). Le champ
  `sin_addr` est déjà en ordre réseau, car il vient de `inet_pton`/`getaddrinfo`.
- `getsockname` écrit dans `len`, donc on l'initialise à `sizeof(local)` avant.
- On `close(fd)` dans tous les cas, y compris sur erreur (pas de fuite de descripteur).

### Comment vérifier

```
sudo ./ft_nmap --ip 127.0.0.1                  # attendu : Source IP : 127.0.0.1
sudo ./ft_nmap --ip scanme.nmap.org            # attendu : l'IP de ta VM (voir `ip -4 addr`)
```

Si les deux donnent des IP différentes, c'est normal et c'est justement la preuve
que la route dépend de la destination.

### Question de soutenance probable

« Pourquoi ne pas simplement prendre la première IP de l'interface ? »
→ Parce qu'avec plusieurs interfaces, la bonne source dépend de la route vers la
cible. Le noyau est le seul à connaître la table de routage, donc on lui demande.

### Prochaine étape (phase 2, étape 2)

Construire l'en-tête IP + l'en-tête TCP, calculer le checksum avec le
pseudo-header, puis envoyer avec `sendto`.

---

## Phase 2, étape 2 : construire le paquet SYN et l'envoyer

### Vue d'ensemble : un paquet = des octets dans un tableau

Un paquet réseau n'est rien d'autre qu'une suite d'octets. Ici, 40 octets :

```
| En-tête IP (20 octets) | En-tête TCP (20 octets) |
```

On remplit un tableau `uint8_t packet[40]`, puis on le donne au noyau avec
`sendto`. Les structs `struct iphdr` et `struct tcphdr` (fournies par
`<netinet/ip.h>` et `<netinet/tcp.h>`) sont juste des « calques » posés sur ce
tableau pour nommer les champs. Il n'y a pas de padding à craindre : ces structs
sont faites pour correspondre exactement au format du fil.

### 1. Le raw socket et `IP_HDRINCL`

`socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` donne un socket qui laisse passer des
paquets non construits par le noyau. Par défaut le noyau ajoute lui-même
l'en-tête IP. Avec `setsockopt(IP_HDRINCL, 1)`, on lui dit : « le buffer que je
t'envoie commence déjà par l'en-tête IP, ne le rajoute pas ». C'est ce qui nous
permet de maîtriser tous les champs (et plus tard de spoofer la source en bonus).
Il faut être root (`CAP_NET_RAW`), d'où le `check_root`.

### 2. L'en-tête IP (`fill_ip`)

| Champ | Valeur | Pourquoi |
|---|---|---|
| `version` | 4 | IPv4 |
| `ihl` | 5 | longueur de l'en-tête en mots de 32 bits : 5 × 4 = 20 octets (pas d'options) |
| `tot_len` | 40 | taille totale du paquet, en `htons` |
| `id` | aléatoire | identifiant, sert seulement à la fragmentation |
| `frag_off` | 0 | pas de fragmentation |
| `ttl` | 64 | nombre de sauts max avant que le paquet soit jeté |
| `protocol` | `IPPROTO_TCP` (6) | dit au destinataire ce qu'il y a après l'en-tête IP |
| `saddr` / `daddr` | src (étape 1) / cible | déjà en ordre réseau |
| `check` | checksum IP | mis à 0 pendant le calcul, puis rempli |

### 3. L'en-tête TCP (`fill_tcp`)

- `source` / `dest` : ports, en `htons`. Port source fixe pour l'instant (40000).
  Plus tard, un port différent par type de scan permettra de reconnaître les réponses.
- `seq` : numéro de séquence aléatoire. `ack_seq` reste à 0 (rien à acquitter dans un SYN).
- `doff` = 5 : longueur de l'en-tête TCP en mots de 32 bits (20 octets, pas d'options).
- Les **flags** : `syn = 1`, tous les autres à 0. C'est la **seule chose qui change
  d'un type de scan à l'autre** (SYN, NULL = aucun, FIN, XMAS = FIN+PSH+URG, ACK).
  Le code convertit un masque (`TH_SYN`, `TH_ACK`...) en bits de la struct.
- `window` = 1024 : taille de fenêtre annoncée, valeur quelconque.

### 4. Le checksum : le point où tout casse

**Algorithme (RFC 1071)** :
1. Découper les données en mots de 16 bits.
2. Les additionner dans un entier 32 bits.
3. Replier les retenues : tant que `sum >> 16`, faire `sum = (sum & 0xFFFF) + (sum >> 16)`.
4. Prendre le complément à un (`~sum`).
5. Si le nombre d'octets est impair, le dernier octet est complété par un 0.

**Propriété pratique pour déboguer** : si on recalcule le checksum sur des
données qui contiennent *déjà* leur bon checksum, on obtient **0**. C'est le test
que j'ai fait sans réseau : checksum IP = 0 et checksum TCP = 0.

**Le pseudo-header (TCP uniquement)** : le checksum TCP ne couvre pas que le
segment TCP, il couvre aussi 12 octets « virtuels » placés devant, qui ne sont
jamais envoyés :

```
| IP source (4) | IP destination (4) | 0 (1) | protocole = 6 (1) | longueur TCP (2) |
```

Pourquoi ? Pour que TCP détecte un paquet livré à la mauvaise adresse, alors que
TCP ne voit pas l'en-tête IP. Conséquence : **si l'IP source est fausse, le
checksum est faux**, et la cible jette le paquet sans rien dire. Aucun message
d'erreur : c'est la cause n°1 de « mon scan ne marche pas ».

Notre code lit les octets deux par deux en big-endian, donc le résultat ne
dépend ni de l'endianness de la machine ni de l'alignement mémoire. On le range
avec `htons`.

### 5. Byte order, rappel

Le réseau est en **big-endian**. Nos x86 sont en little-endian. Donc :
- ports, `tot_len`, `id`, `seq`, `window` : `htons` / `htonl` ;
- adresses : déjà en ordre réseau (`inet_pton`, `getaddrinfo`), on ne les touche pas.

Oublier un `htons` donne par exemple un SYN vers le port 20480 au lieu de 80.

### 6. Comment vérifier

```
# terminal 1
sudo tcpdump -i any -nn -v 'tcp port 80 and host 45.33.32.156'
# terminal 2
sudo ./ft_nmap --ip scanme.nmap.org --ports 80 --scan SYN
```

Dans tcpdump, on doit voir `Flags [S]` et surtout **`cksum 0x.... (correct)`**
pour l'IP et pour le TCP. Si on lit `(incorrect)`, le bug est dans le checksum
ou dans l'IP source. Sur une VM VirtualBox en NAT on ne verra peut-être pas de
réponse ici, c'est normal : la réception, c'est l'étape 3 (pcap).

### Question de soutenance probable

« À quoi sert le pseudo-header ? » → à lier le segment TCP aux adresses IP, pour
détecter une mauvaise livraison, même si TCP ne voit pas l'en-tête IP.

### Prochaine étape (phase 2, étape 3)

Capturer la réponse avec pcap (ouverture de l'interface, filtre, `pcap_dispatch`).
