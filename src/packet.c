#include "ft_nmap.h"

/*
** Checksum Internet (RFC 1071) : somme des mots de 16 bits en complément à un.
** On lit les octets deux par deux en big-endian pour ne pas dépendre de
** l'endianness ni de l'alignement ; le résultat est rendu en ordre réseau.
*/
uint16_t	checksum(const void *data, size_t len)
{
	const uint8_t	*bytes;
	uint32_t		sum;
	size_t			i;

	bytes = data;
	sum = 0;
	i = 0;
	while (i + 1 < len)
	{
		sum += (uint32_t)(bytes[i] << 8 | bytes[i + 1]);
		i += 2;
	}
	if (i < len)
		sum += (uint32_t)(bytes[i] << 8);
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (htons((uint16_t)~sum));
}

/* Pseudo-header : jamais envoyé, seulement ajouté devant le segment TCP
** pour le calcul du checksum (RFC 793). */
struct s_pseudo
{
	uint32_t	saddr;
	uint32_t	daddr;
	uint8_t		zero;
	uint8_t		proto;
	uint16_t	tcp_len;
}	__attribute__((packed));

static uint16_t	tcp_checksum(const t_probe *probe, const struct tcphdr *tcp)
{
	uint8_t			buf[sizeof(struct s_pseudo) + sizeof(struct tcphdr)];
	struct s_pseudo	pseudo;

	pseudo.saddr = probe->src.s_addr;
	pseudo.daddr = probe->dst.s_addr;
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_TCP;
	pseudo.tcp_len = htons(sizeof(struct tcphdr));
	memcpy(buf, &pseudo, sizeof(pseudo));
	memcpy(buf + sizeof(pseudo), tcp, sizeof(struct tcphdr));
	return (checksum(buf, sizeof(buf)));
}

static void	fill_ip(struct iphdr *ip, const t_probe *probe)
{
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(PACKET_SIZE);
	ip->id = htons((uint16_t)rand());
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	ip->saddr = probe->src.s_addr;
	ip->daddr = probe->dst.s_addr;
	ip->check = checksum(ip, sizeof(struct iphdr));
}

static void	fill_tcp(struct tcphdr *tcp, const t_probe *probe)
{
	memset(tcp, 0, sizeof(*tcp));
	tcp->source = htons(probe->sport);
	tcp->dest = htons(probe->dport);
	tcp->seq = htonl((uint32_t)rand());
	tcp->doff = 5;
	tcp->fin = !!(probe->flags & TH_FIN);
	tcp->syn = !!(probe->flags & TH_SYN);
	tcp->rst = !!(probe->flags & TH_RST);
	tcp->psh = !!(probe->flags & TH_PUSH);
	tcp->ack = !!(probe->flags & TH_ACK);
	tcp->urg = !!(probe->flags & TH_URG);
	tcp->window = htons(1024);
	tcp->check = tcp_checksum(probe, tcp);
}

/* Écrit un paquet IP + TCP sans options (40 octets) dans buf. */
void	build_tcp_packet(uint8_t *buf, const t_probe *probe)
{
	fill_ip((struct iphdr *)buf, probe);
	fill_tcp((struct tcphdr *)(buf + sizeof(struct iphdr)), probe);
}

/* Raw socket TCP où l'on fournit nous-mêmes l'en-tête IP (IP_HDRINCL). */
int	open_raw_socket(void)
{
	int	fd;
	int	on;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (fd < 0)
		return (perror("socket"), -1);
	on = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt IP_HDRINCL");
		close(fd);
		return (-1);
	}
	return (fd);
}

int	send_tcp_probe(int fd, const t_probe *probe)
{
	uint8_t				packet[PACKET_SIZE];
	struct sockaddr_in	to;

	build_tcp_packet(packet, probe);
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = probe->dst;
	if (sendto(fd, packet, sizeof(packet), 0,
			(struct sockaddr *)&to, sizeof(to)) < 0)
		return (perror("sendto"), 1);
	return (0);
}
