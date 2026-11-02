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

    /* Test temporaire de la phase 2 : 1 SYN vers le 1er port de la 1re
    ** cible, puis lecture de la réponse (à retirer ensuite). */
    {
        t_probe     probe;
        t_capture   cap;
        int         fd;

        probe.dst = options.targets[0].addr;
        probe.sport = 40000;
        probe.dport = (uint16_t)options.ports[0];
        probe.flags = TH_SYN;
        fd = open_raw_socket();
        if (fd >= 0 && get_source_ip(probe.dst, &probe.src) == 0
            && open_capture(&cap, probe.dst) == 0)
        {
            if (send_tcp_probe(fd, &probe) == 0)
                printf("Port %u : %s\n", probe.dport,
                    state_name(wait_response(&cap, &probe, 2000)));
            close_capture(&cap);
        }
        if (fd >= 0)
            close(fd);
    }

    /* Ensuite : lancer les scans. */

    free_targets(&options);
    free(options.ports);
    return 0;
}
