#include "ft_nmap.h"

int main(int argc, char **argv)
{
    t_options   options;

    memset(&options, 0, sizeof(options));
    if (parse_args(argc, argv, &options) != 0)
    {
        free(options.ports);
        return 1;
    }

    /* Ensuite : résoudre les cibles et lancer les scans. */

    free(options.ports);
    return 0;
}
