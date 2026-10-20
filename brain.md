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
