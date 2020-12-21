#include "prot.h"

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    fprintf(stdout , "TIME: %s",ctime((const time_t*)&pkthdr->ts.tv_sec));
    u_short type = ether_handler(args,pkthdr,packet);

    if(type == ETHERTYPE_IP)
    {
        ip_handler(args , pkthdr , packet);
    }

    fprintf(stdout , "\n");
}



#define ICMP 0x01
#define TCP 0x06
#define UDP 0x11

//reverse endian
uint16_t r16(uint16_t bytes)
{
    uint16_t aux = 0;
    uint8_t byte;
    int i;

    for(i = 0; i < 16; i+=8)
    {
        byte = (bytes >> i) & 0xff;
        aux |= byte << (16 - 8 - i);
    }
    return aux;
}

uint32_t r32(uint32_t bytes){

    uint32_t aux = 0;
    uint8_t byte;
    int i;

    for(i = 0; i < 32; i+=8)
    {
        byte = (bytes >> i) & 0xff;
        aux |= byte << (32 - 8 - i);
    }
    return aux;
}

u_int16_t ether_handler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){

    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct m_ether_header *eptr;
    u_short ether_type;

    eptr = (struct m_ether_header *)packet;
    ether_type = ntohs(eptr->ether_type);

    fprintf(stdout,"SRC MAC: ");
    fprintf(stdout,"%s\n"
            ,ether_ntoa((struct m_ether_addr*)eptr->ether_shost));
    fprintf(stdout,"DES MAC: ");
    fprintf(stdout,"%s\n" , ether_ntoa((struct m_ether_addr*)eptr->ether_dhost));


    if (ether_type == 0x0200){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_PUP");
    }else if (ether_type == 0x8035){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_REVARP");
    }else if (ether_type == 0x0500){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_SPRITE");
    }else if (ether_type == 0x0800){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_IP");
    }else if (ether_type == 0x0806){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_ARP");
    }else if (ether_type == 0x809B){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_AT");
    }else if (ether_type == 0x80F3){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_AARP");
    }else if (ether_type == 0x8100){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_VLAN");
    }else if (ether_type == 0x8137){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_IPX");
    }else if (ether_type == 0x86dd){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_IPV6");
    }else if (ether_type == 0x9000){
        fprintf(stdout , "ETHER TYPE: %s\n" , "ETHERTYPE_LOOPBACK");
    }      

    return ether_type;

}

u_char* ip_handler (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct m_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;
    int len;
    
    ip = (struct m_ip*)(packet + sizeof(struct m_ether_header));
    length -= sizeof(struct ether_header); 

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip);
    version = IP_V(ip);

    //Only handle IPv4 proto
    fprintf(stdout,"\tIP VERSION %d\n",version);
    if(version != 4) return NULL;
    fprintf(stdout,"\tSRC IP: %s\n", inet_ntoa(ip->ip_src));
    fprintf(stdout,"\tDST IP: %s\n", inet_ntoa(ip->ip_dst));
    fprintf(stdout , "\tTTL: %d\n" , ip->ip_ttl);
    if(ip->ip_p == ICMP){
        fprintf(stdout,"\tFOR PROTO: %s\n" , "ICMP");
    }else if(ip->ip_p == TCP){
        fprintf(stdout,"\tFOR PROTO: %s\n" , "TCP");
        tcp_handler(args , pkthdr , packet);
    }else if(ip->ip_p == UDP){
        fprintf(stdout,"\tFOR PROTO: %s\n" , "UDP");
        udp_handler(args , pkthdr , packet);
    }else{
        fprintf(stdout,"\tUNKNOWN PROTO , ID is: %x" , ip->ip_p);   
    }


    return NULL;
}

u_char* tcp_handler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){

    const struct m_tcphdr *tcp;
    tcp = (struct m_tcphdr *)(packet + sizeof(struct  m_ether_header) + sizeof(struct m_ip));
    fprintf(stdout , "\t\tSRC PORT: %hd" , r16(tcp->th_sport));
    fprintf(stdout , "\t\tDST PORT: %hd\n" , r16(tcp->th_dport));
    fprintf(stdout , "\t\tRAW SEQ: %u\tRAW ACK: %u\n" , r32(tcp->th_seq) , r32(tcp->th_ack));
}

u_char* udp_handler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){

    const struct m_udphdr *udp;
    udp = (struct m_tcphdr *)(packet + sizeof(struct  m_ether_header) + sizeof(struct m_ip));
    fprintf(stdout , "\t\tSRC PORT: %hd" , r16(udp->uh_sport));
    fprintf(stdout , "\t\tDST PORT: %hd\n" , r16(udp->uh_dport));
}
