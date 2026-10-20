#include "ft_nmap.h"

/*
** Retrouve l'IP source que le noyau utiliserait pour joindre `dst`.
** Un connect() sur un socket UDP n'envoie aucun paquet : il choisit
** seulement la route, et getsockname() nous dit quelle IP locale en résulte.
*/
int	get_source_ip(struct in_addr dst, struct in_addr *src)
{
	struct sockaddr_in	remote;
	struct sockaddr_in	local;
	socklen_t			len;
	int					fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return (perror("socket"), 1);
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(53);
	remote.sin_addr = dst;
	len = sizeof(local);
	if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0
		|| getsockname(fd, (struct sockaddr *)&local, &len) < 0)
	{
		perror("source ip");
		close(fd);
		return (1);
	}
	close(fd);
	*src = local.sin_addr;
	return (0);
}
