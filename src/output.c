#include "ft_nmap.h"

static void	print_target(const t_target *target)
{
	char	ip[INET_ADDRSTRLEN];

	if (inet_ntop(AF_INET, &target->addr, ip, sizeof(ip)) == NULL)
		strcpy(ip, "?");
	if (strcmp(ip, target->name) == 0)
		printf("Target Ip-Address : %s\n", ip);
	else
		printf("Target Ip-Address : %s (%s)\n", ip, target->name);
}

/* Ordre d'affichage identique aux exemples du sujet. */
static void	print_scans(const t_options *options)
{
	printf("Scans to be performed :");
	if (options->scan_syn)
		printf(" SYN");
	if (options->scan_null)
		printf(" NULL");
	if (options->scan_fin)
		printf(" FIN");
	if (options->scan_xmas)
		printf(" XMAS");
	if (options->scan_ack)
		printf(" ACK");
	if (options->scan_udp)
		printf(" UDP");
	printf("\n");
}

void	print_config(const t_options *options)
{
	size_t	i;

	printf("Scan Configurations\n");
	i = 0;
	while (i < options->target_count)
		print_target(&options->targets[i++]);
	printf("No of Ports to scan : %zu\n", options->port_count);
	print_scans(options);
	printf("No of threads : %d\n", options->thread_count);
}
