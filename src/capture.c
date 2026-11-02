#include "ft_nmap.h"

/* Taille de l'en-tête de la couche liaison, selon pcap_datalink(). */
static int	link_offset(int dlt)
{
	if (dlt == DLT_EN10MB)
		return (14);
	if (dlt == DLT_LINUX_SLL)
		return (16);
	if (dlt == DLT_NULL)
		return (4);
	if (dlt == DLT_RAW)
		return (0);
	return (-1);
}

const char	*state_name(t_state state)
{
	if (state == STATE_OPEN)
		return ("Open");
	if (state == STATE_CLOSED)
		return ("Closed");
	if (state == STATE_FILTERED)
		return ("Filtered");
	return ("No response");
}

/* Réponse TCP : le port source est le port scanné, le port destination
** est le port source de notre sonde. */
static t_state	parse_tcp(const struct tcphdr *tcp, const t_probe *probe)
{
	if (ntohs(tcp->source) != probe->dport || ntohs(tcp->dest) != probe->sport)
		return (STATE_NONE);
	if (tcp->rst)
		return (STATE_CLOSED);
	if (tcp->syn && tcp->ack)
		return (STATE_OPEN);
	return (STATE_NONE);
}

/* Un ICMP « destination unreachable » contient l'en-tête IP et les 8
** premiers octets de notre sonde : on vérifie qu'elle est bien la nôtre. */
static t_state	parse_icmp(const uint8_t *data, size_t len, const t_probe *probe)
{
	const struct icmphdr	*icmp;
	const struct iphdr		*inner;
	const struct tcphdr		*tcp;
	size_t					inner_len;

	if (len < sizeof(*icmp) + sizeof(*inner))
		return (STATE_NONE);
	icmp = (const struct icmphdr *)data;
	inner = (const struct iphdr *)(data + sizeof(*icmp));
	inner_len = (size_t)inner->ihl * 4;
	if (icmp->type != ICMP_DEST_UNREACH || inner->protocol != IPPROTO_TCP
		|| len < sizeof(*icmp) + inner_len + 8)
		return (STATE_NONE);
	tcp = (const struct tcphdr *)(data + sizeof(*icmp) + inner_len);
	if (inner->daddr != probe->dst.s_addr || ntohs(tcp->source) != probe->sport
		|| ntohs(tcp->dest) != probe->dport)
		return (STATE_NONE);
	return (STATE_FILTERED);
}

static void	on_packet(uint8_t *user, const struct pcap_pkthdr *hdr,
	const uint8_t *bytes)
{
	t_capture		*cap;
	const struct iphdr	*ip;
	size_t			ip_len;
	t_state			state;

	cap = (t_capture *)user;
	if (hdr->caplen < (size_t)cap->offset + sizeof(*ip))
		return ;
	ip = (const struct iphdr *)(bytes + cap->offset);
	ip_len = (size_t)ip->ihl * 4;
	if (ip->version != 4 || ip_len < sizeof(*ip)
		|| hdr->caplen < cap->offset + ip_len)
		return ;
	state = STATE_NONE;
	if (ip->protocol == IPPROTO_TCP
		&& hdr->caplen >= cap->offset + ip_len + sizeof(struct tcphdr))
		state = parse_tcp((const struct tcphdr *)((const uint8_t *)ip + ip_len),
				&cap->probe);
	else if (ip->protocol == IPPROTO_ICMP)
		state = parse_icmp((const uint8_t *)ip + ip_len,
				hdr->caplen - cap->offset - ip_len, &cap->probe);
	if (state != STATE_NONE)
		cap->state = state;
}

/* À appeler AVANT d'envoyer la sonde, sinon on peut rater une réponse rapide. */
int	open_capture(t_capture *cap, struct in_addr dst)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	char				filter[128];
	char				ip[INET_ADDRSTRLEN];
	struct bpf_program	prog;

	cap->handle = pcap_open_live("any", 128, 0, 100, errbuf);
	if (!cap->handle)
		return (fprintf(stderr, "pcap_open_live: %s\n", errbuf), -1);
	cap->offset = link_offset(pcap_datalink(cap->handle));
	if (cap->offset < 0)
	{
		fprintf(stderr, "Type de liaison non géré par pcap\n");
		return (pcap_close(cap->handle), -1);
	}
	inet_ntop(AF_INET, &dst, ip, sizeof(ip));
	snprintf(filter, sizeof(filter), "(tcp and src host %s) or icmp", ip);
	if (pcap_compile(cap->handle, &prog, filter, 1, PCAP_NETMASK_UNKNOWN) < 0
		|| pcap_setfilter(cap->handle, &prog) < 0)
	{
		fprintf(stderr, "pcap filter: %s\n", pcap_geterr(cap->handle));
		return (pcap_close(cap->handle), -1);
	}
	pcap_freecode(&prog);
	return (0);
}

/* Lit les paquets jusqu'à une réponse ou jusqu'au timeout.
** Pas de réponse : STATE_FILTERED (le tri fin viendra avec les autres scans). */
t_state	wait_response(t_capture *cap, const t_probe *probe, int timeout_ms)
{
	struct timespec	start;
	struct timespec	now;

	cap->probe = *probe;
	cap->state = STATE_NONE;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (cap->state == STATE_NONE)
	{
		pcap_dispatch(cap->handle, -1, on_packet, (uint8_t *)cap);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if ((now.tv_sec - start.tv_sec) * 1000
			+ (now.tv_nsec - start.tv_nsec) / 1000000 >= timeout_ms)
			break ;
	}
	if (cap->state == STATE_NONE)
		return (STATE_FILTERED);
	return (cap->state);
}

void	close_capture(t_capture *cap)
{
	if (cap->handle)
		pcap_close(cap->handle);
	cap->handle = NULL;
}
