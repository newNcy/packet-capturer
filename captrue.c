#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>



/* mac protocol */
struct eth2_mac_header
{
    char dst[6];
    char src[6];
    uint16_t type;
}__attribute__((packed));
typedef struct eth2_mac_header eth2_mac_header;

struct fixed_ip_header 
{

    u_char ver_hlen;
    u_char servers;
    uint16_t length;
    uint16_t ident;
    uint16_t flag_offset;
    u_char ttl;
    u_char protocol;
    uint16_t check_sum;
    u_char src_ip[32];
    u_char dst_ip[32];
}__attribute__((packed));
typedef struct fixed_ip_header fixed_ip_header;

struct fixed_tcp_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t doffset_keep_flags;
    uint16_t wnd;
    uint16_t check_sum;
    uint16_t urg;
}__attribute__((packed));

typedef struct fixed_tcp_header fixed_tcp_header;
/* internet protocol */
#define ETH_IP 0x0800
#define ETH_ARP 0x0806
#define ETH_RARP 0x8035
#define ETH_IPV6 0x86dd
/* ip protoclol */
#define IP_ICMP 1
#define IP_IGMP 2
#define IP_IP   4
#define IP_TCP  6
#define IP_EGP  8
#define IP_IGP  9
#define IP_UDP  17
#define IP_IPV6 41
#define IP_ESP  50
#define IP_OSPF 89
/* apply */

/* util funcs */
void turn_endian(char * buff,int len) 
{
    char rbuff[128] = {0};
    for (int i = 0; i < len; ++ i) {
        rbuff[i] = buff[len-i-1];
    }
    for (int i = 0; i < len; ++ i) {
        buff[i] = rbuff[i];
    }
}

void title(char *data)
{
    printf("[\e[032m%s\e[0m]\n",data);
}

void bin_byte(char *data,int len)
{
    for (int i = 0 ; i < len; i++) {
        for (int j = 0; j < 8; j ++) {
            printf("%d",(data[i]&(1<<(7-j)))>>(7-j));
        } 
        printf(" ");
    }
}
void print_byte(char * note, char * data,int len)
{
    printf("%s:",note);
    for (int i = 0 ; i < len; ++i) {
        printf("%02x ",data[i] & 0xff);
    }
    printf("\n");
}
void print_mac(char * note, char * data)
{
    printf("%s:",note);
    for (int i = 0 ; i < 4; ++i) {
        printf("%02x:",data[i] & 0xff);
    }
    printf("%02x",data[5] & 0xff);
    printf("\n");
}

void print_ip(char * note,char * data)
{
    printf("%s:",note);
    for (int i = 0; i < 3; ++ i) {
        printf("%d.",data[i]&0xff);
    }
    printf("%d",data[3] & 0xff);
    printf("\n");
}

/* transmision */
#define TCP_URG(TCP) ((TCP->doffset_keep_flags&0x20)>>5)
#define TCP_ACK(TCP) ((TCP->doffset_keep_flags&0x10)>>4)
#define TCP_PSH(TCP) ((TCP->doffset_keep_flags&0x08)>>3)
#define TCP_RST(TCP) ((TCP->doffset_keep_flags&0x04)>>2)
#define TCP_SYN(TCP) ((TCP->doffset_keep_flags&0x02)>>1)
#define TCP_FIN(TCP) (TCP->doffset_keep_flags&0x01)
void parse_tcp_header(char *buff)
{
    title("TCP");
    fixed_tcp_header * tcp_header = (fixed_tcp_header*)buff;
    print_byte("",buff,20);
    turn_endian((char*)&(tcp_header->src_port),2);
    turn_endian((char*)&(tcp_header->dst_port),2);
    turn_endian((char*)&(tcp_header->doffset_keep_flags),2);
    //turn_endian((char*)&(tcp_header->seq),4);
    //turn_endian((char*)&(tcp_header->ack),4);
    printf("src port:%u  dst port:%u\n",tcp_header->src_port,tcp_header->dst_port);
    printf("seq:%u\n",tcp_header->seq);
    printf("ack:%u\n",tcp_header->ack);
    printf("data offet:%d\n",tcp_header->doffset_keep_flags>>12);
    bin_byte((char *)&(tcp_header->doffset_keep_flags),2);
    printf("URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n",
           TCP_URG(tcp_header),
           TCP_ACK(tcp_header),
           TCP_PSH(tcp_header),
           TCP_RST(tcp_header),
           TCP_SYN(tcp_header),
           TCP_FIN(tcp_header)
           );
}


/* internet */
void parse_ip_header(char * buff)
{
    title("IP");
    fixed_ip_header * ip_header = (fixed_ip_header*)buff;
    turn_endian((char*)&(ip_header->length),2);
    turn_endian((char*)&(ip_header->ident),2);
    printf("version:%d\n",ip_header->ver_hlen>>4);
    printf("head_len:%d\n",ip_header->ver_hlen&0x0f);
    printf("length:%d\n",ip_header->length);
    printf("ident:%d\n",ip_header->ident);
    int flag = ip_header->flag_offset>>13; 
    printf("MF:%d DF:%d\n",(flag&4)>>2,(flag&2)>>1); // 
    printf("offset:%d\n",ip_header->flag_offset&0x07fff); //
    printf("ttl:%d\n",ip_header->ttl); //
    printf("protocol:%d ",ip_header->protocol); //
#define IP_CASE(P,OP) \
    case P:\
        printf(#P"\n");\
        print_ip("sip",(char*)&(ip_header->src_ip));\
        print_ip("dip",(char*)&(ip_header->dst_ip));\
        OP;\
    break;
    buff += (ip_header->ver_hlen&0xf)*4;
    switch(ip_header->protocol) {
        IP_CASE(IP_ICMP,);
        IP_CASE(IP_IGMP,);
        IP_CASE(IP_IP,);
        IP_CASE(IP_TCP,parse_tcp_header(buff));
        IP_CASE(IP_EGP,);
        IP_CASE(IP_IGP,);
        IP_CASE(IP_UDP,);
        IP_CASE(IP_IPV6,);
        IP_CASE(IP_ESP,);
        IP_CASE(IP_OSPF,);
    }

}
void parse_arp_header(char * buff)
{
}
void parse_rarp_header(char *buff)
{

}
/* mac */

void parse_mac_header(char * buff)
{

    eth2_mac_header *frame = (eth2_mac_header*)buff;
    turn_endian((char*)&(frame->type),2);
    if (frame->type > 0x600) {
        title("ETH]");
    }else {
        title("IEEE802.3");
    }
    print_mac("to",frame->dst);
    print_mac("from",frame->src);
    if ( frame->type < 0x600) {
        printf("[len]%04x\n",frame->type);
    }else {
        printf("[type]%04x ",frame->type);
#define ETH_CASE(T,OP) \
        case T:\
            printf(#T"\n");\
            OP;\
        break;
        buff += sizeof(eth2_mac_header);
        //print_byte("data",buff,20);
        switch(frame->type) {
            ETH_CASE(ETH_IP,parse_ip_header(buff));
            ETH_CASE(ETH_ARP,parse_arp_header(buff));
            ETH_CASE(ETH_RARP,parse_rarp_header(buff));
        }
    }
}


/* global variablies */
static int finish = 0;
static int packet_count = 0;
static int socket_id = 0;
/*********************/
void on_sigint(int s)
{
    if (s == SIGINT) {
        finish = 1;
        printf("\nfinish\n[%d]packets captured\n",packet_count);
        close(socket_id);
        exit(EXIT_SUCCESS);
    }
}

void capture()
{
    socket_id = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_id < 0 ) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    for (;;) {
        if (finish) break;
        unsigned char buff[1500] = {0};
        memset(buff,0,1500);
        int rc = recvfrom(socket_id,buff,1500,0,NULL,NULL);
        printf("\nframe:%d byte\n",rc);
        parse_mac_header(buff);
        packet_count ++;
        putchar('\n');
    }
}


int main ()
{
#ifdef __BIG_ENDIAN
    printf("BBBBBB");
#endif
    signal(SIGINT, on_sigint);
    capture();
}
