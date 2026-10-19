#include "ft_nmap.h"

/* args.c */
void    print_help(void)
{
    printf("Usage: ./ft_nmap [OPTIONS]\n");
    printf("  --help                 Display this help\n");
    printf("  --ip ADDRESS           Target IPv4 address or hostname\n");
    printf("  --file FILE            Read targets from a file\n");
    printf("  --ports LIST           Ports, e.g. 1-10,22,80\n");
    printf("  --speedup NUMBER       Number of threads (max: 250)\n");
    printf("  --scan TYPES           SYN,NULL,FIN,XMAS,ACK,UDP\n");
}