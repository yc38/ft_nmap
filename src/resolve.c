#include "ft_nmap.h"

/* IPv4 en notation pointée d'abord, sinon hostname/FQDN via getaddrinfo. */
static int	resolve_one(const char *name, struct in_addr *addr)
{
	struct addrinfo	hints;
	struct addrinfo	*result;
	int				ret;

	if (inet_pton(AF_INET, name, addr) == 1)
		return (0);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(name, NULL, &hints, &result);
	if (ret != 0)
	{
		fprintf(stderr, "Attention : impossible de résoudre %s : %s\n",
			name, gai_strerror(ret));
		return (1);
	}
	*addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr;
	freeaddrinfo(result);
	return (0);
}

/* Les cibles non résolues sont retirées ; erreur s'il n'en reste aucune. */
int	resolve_targets(t_options *options)
{
	size_t	i;
	size_t	kept;

	i = 0;
	kept = 0;
	while (i < options->target_count)
	{
		if (resolve_one(options->targets[i].name,
				&options->targets[i].addr) == 0)
			options->targets[kept++] = options->targets[i];
		else
			free(options->targets[i].name);
		i++;
	}
	options->target_count = kept;
	if (kept == 0)
	{
		fprintf(stderr, "Erreur : aucune cible valide.\n");
		return (1);
	}
	return (0);
}
