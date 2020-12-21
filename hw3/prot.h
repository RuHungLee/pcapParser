#include <time.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/ip.h> 

#define ETHERTYPE_PUP       0x0200          /* Xerox PUP */
#define ETHERTYPE_SPRITE    0x0500      /* Sprite */
#define ETHERTYPE_IP        0x0800      /* IP */
#define ETHERTYPE_ARP       0x0806      /* Address resolution */
#define ETHERTYPE_REVARP    0x8035      /* Reverse ARP */
#define ETHERTYPE_AT        0x809B      /* AppleTalk protocol */
#define ETHERTYPE_AARP      0x80F3      /* AppleTalk ARP */
#define ETHERTYPE_VLAN      0x8100      /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX       0x8137      /* IPX */
#define ETHERTYPE_IPV6      0x86dd      /* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK  0x9000      /* used to test interfaces */

u_char* ip_handler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_char* tcp_handler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_char* udp_handler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
u_short ether_handler(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
uint16_t r16(uint16_t bytes);
uint32_t r32(uint32_t bytes);

#define IP_V(ip)  (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)

struct m_ip
  {
    u_int8_t  ip_vhl;   /* header length, version */
#define IP_V(ip)  (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
    uint8_t ip_tos;			/* type of service */
    unsigned short ip_len;		/* total length */
    unsigned short ip_id;		/* identification */
    unsigned short ip_off;		/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    unsigned short ip_sum;		/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
  };


struct m_ether_addr
{
  uint8_t ether_addr_octet[ETH_ALEN];
} __attribute__ ((__packed__));


struct m_ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];   /* destination eth addr */
  uint8_t  ether_shost[ETH_ALEN];   /* source ether addr    */
  uint16_t ether_type;              /* packet type ID field */
} __attribute__ ((__packed__));

typedef uint32_t tcp_seq;

struct m_udphdr
{
  __extension__ union
  {
    struct
    {
      uint16_t uh_sport;  /* source port */
      uint16_t uh_dport;  /* destination port */
      uint16_t uh_ulen;   /* udp length */
      uint16_t uh_sum;    /* udp checksum */
    };
    struct
    {
      uint16_t source;
      uint16_t dest;
      uint16_t len;
      uint16_t check;
    };
  };
};

struct m_tcphdr
  {
    __extension__ union
    {
      struct
      {
  uint16_t th_sport;  /* source port */
  uint16_t th_dport;  /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
  uint8_t th_x2:4;  /* (unused) */
  uint8_t th_off:4; /* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
  uint8_t th_off:4; /* data offset */
  uint8_t th_x2:4;  /* (unused) */
# endif
  uint8_t th_flags;
# define TH_FIN 0x01
# define TH_SYN 0x02
# define TH_RST 0x04
# define TH_PUSH  0x08
# define TH_ACK 0x10
# define TH_URG 0x20
  uint16_t th_win;  /* window */
  uint16_t th_sum;  /* checksum */
  uint16_t th_urp;  /* urgent pointer */
      };
      struct
      {
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
  uint16_t res1:4;
  uint16_t doff:4;
  uint16_t fin:1;
  uint16_t syn:1;
  uint16_t rst:1;
  uint16_t psh:1;
  uint16_t ack:1;
  uint16_t urg:1;
  uint16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
  uint16_t doff:4;
  uint16_t res1:4;
  uint16_t res2:2;
  uint16_t urg:1;
  uint16_t ack:1;
  uint16_t psh:1;
  uint16_t rst:1;
  uint16_t syn:1;
  uint16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
      };
    };
};