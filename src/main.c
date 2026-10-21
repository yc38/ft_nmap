#include "ft_nmap.h"

/* Les raw sockets exigent les droits root (UID effectif 0). */
static int  check_root(void)
{
    if (geteuid() != 0)
    {
        fprintf(stderr, "Erreur : ft_nmap doit être lancé en root "
            "(raw sockets). Essaie : sudo ./ft_nmap ...\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    t_options   options;

    memset(&options, 0, sizeof(options));
    if (parse_args(argc, argv, &options) != 0
        || check_root() != 0
        || resolve_targets(&options) != 0)
    {
        free_targets(&options);
        free(options.ports);
        return 1;
    }

    print_config(&options);

    /* Test temporaire de la phase 2, étapes 1-2 : 1 SYN vers le 1er port
    ** de la 1re cible (à retirer ensuite). */
    {
        t_probe probe;
        int     fd;

        probe.dst = options.targets[0].addr;
        probe.sport = 40000;
        probe.dport = (uint16_t)options.ports[0];
        probe.flags = TH_SYN;
        fd = open_raw_socket();
        if (fd >= 0 && get_source_ip(probe.dst, &probe.src) == 0
            && send_tcp_probe(fd, &probe) == 0)
            printf("[debug] SYN envoyé vers le port %u\n", probe.dport);
        if (fd >= 0)
            close(fd);
    }

    /* Ensuite : lancer les scans. */

    free_targets(&options);
    free(options.ports);
    return 0;
}
