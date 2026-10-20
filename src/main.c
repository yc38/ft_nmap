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

    /* Test temporaire de la phase 2, étape 1 (à retirer ensuite). */
    {
        struct in_addr  src;
        char            buf[INET_ADDRSTRLEN];

        if (get_source_ip(options.targets[0].addr, &src) == 0)
            printf("[debug] Source IP : %s\n",
                inet_ntop(AF_INET, &src, buf, sizeof(buf)));
    }

    /* Ensuite : lancer les scans. */

    free_targets(&options);
    free(options.ports);
    return 0;
}
