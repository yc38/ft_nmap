#ifndef FT_NMAP_H
# define FT_NMAP_H

/* C standard */
# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <stddef.h>
# include <string.h>
# include <strings.h>
# include <ctype.h>
# include <errno.h>
# include <limits.h>
# include <time.h>

/* Fichiers et système */
# include <unistd.h>
# include <fcntl.h>
# include <sys/types.h>
# include <sys/stat.h>

/* Threads */
# include <pthread.h>

/* Résolution des noms et adresses réseau */
# include <netdb.h>
# include <arpa/inet.h>

/* Sockets et protocoles IPv4 / TCP / UDP / ICMP */
# include <sys/socket.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>

/* Capture réseau */
# include <pcap/pcap.h>

/*structures*/

typedef struct s_target
{
    char            *name;  /* tel qu'écrit par l'utilisateur */
    struct in_addr  addr;   /* IPv4 résolue, en ordre réseau */
}   t_target;

typedef struct s_options
{
    char    *ip;
    char    *file;
    t_target    *targets;
    size_t  target_count;
    int     *ports;
    size_t  port_count;
    int     thread_count;
    int     scan_syn;
    int     scan_null;
    int     scan_ack;
    int     scan_fin;
    int     scan_xmas;
    int     scan_udp;
}   t_options;

int	parse_args(int argc, char **argv, t_options *options);
void	free_targets(t_options *options);
int	resolve_targets(t_options *options);
void	print_config(const t_options *options);
void    print_help(void);
int	get_source_ip(struct in_addr dst, struct in_addr *src);

#endif