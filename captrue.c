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



/* mac protocol */
struct eth2_mac_header
{
    char dst[6];
    char src[6];
    uint16_t type;
};
typedef struct eth2_mac_header eth2_mac_header;

struct fixed_ip_header 
{
    u_char ver_hlen;
    uint32_t header_len;
    char servers[8];
    uint16_t length;
    uint16_t ident;
    uint16_t flag_offset;
    u_char ttl;
    u_char protocol;
    uint16_t check_sum;
    uint32_t src_ip;
    uint32_t dst_ip;
};
typedef struct fixed_ip_header fixed_ip_header;

/* internet protocol */
#define IP 0x0800
#define ARP 0x0806
#define RARP 0x8035
/* ip protoclol */





void tuen_endian(char * buff,int len) 
{
    char rbuff[128] = {0};
    for (int i = 0; i < len; ++ i) {
        rbuff[i] = buff[len-i-1];
    }
    for (int i = 0; i < len; ++ i) {
        buff[i] = rbuff[i];
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



/* internet */
void parse_ip_header(char * buff)
{
    printf("[IP]\n");
    fixed_ip_header * ip_header = (fixed_ip_header*)buff;
    tuen_endian((char*)&(ip_header->length),2);
    tuen_endian((char*)&(ip_header->ident),2);
    printf("version:%d\n",ip_header->ver_hlen>>4);
    printf("head_len:%d\n",(ip_header->ver_hlen)&0xf);
    printf("length:%d\n",ip_header->length);
    printf("ident:%d\n",ip_header->ident);
}

/* mac */

void parse_mac_header(char * buff)
{

    eth2_mac_header *frame = (eth2_mac_header*)buff;
    tuen_endian((char*)&(frame->type),2);
    if (frame->type > 0x600) {
        printf("[ETH2]\n");
    }else {
        printf("[IEEE802.3]\n");
    }
    print_byte("to",frame->dst,6);
    print_byte("from",frame->src,6);
    if ( frame->type < 0x600) {
        printf("[len]%04x\n",frame->type);
    }else {
        printf("[type]%04x ",frame->type);
#define CASE(T,OP) \
        case T:\
            printf(#T"\n");\
            OP;\
        break;

        switch(frame->type) {
            CASE(IP,parse_ip_header(buff+sizeof(eth2_mac_header)));
            CASE(ARP,);
            CASE(RARP,);
        }
    }
}


static int finish = 0;
void on_sigint(int s)
{
    if (s == SIGINT) {
        finish = 1;
    }
}

void capture()
{
    int sid = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sid < 0 ) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    for (;;) {
        if (finish) break;
        unsigned char buff[1500] = {0};
        int rc = recvfrom(sid,buff,1500,0,NULL,NULL);
        printf("\n\nframe: %d\n",rc);
        parse_mac_header(buff);
        putchar('\n');
    }
    printf("\nfinish\n");
    close(sid);
}


int main ()
{
    signal(SIGINT, on_sigint);
    capture();
}
