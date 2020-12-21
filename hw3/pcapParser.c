#include "prot.h"


int main(int argc,char **argv)
{ 
    char errbuf[100];
    u_char* args = NULL;

    pcap_t * fp = pcap_open_offline(argv[1], errbuf);
    if (fp == NULL) {
        fprintf(stderr, "pcap_open_offline : %s\n", errbuf);
        return 0;
    }

    pcap_loop(fp,atoi(argv[2]),my_callback,args);

    return 0;
}

