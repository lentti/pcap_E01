#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


void anal_ethernet(const u_char* packet);
void anal_ip(const u_char* packet);
void printPacket(u_char* packet, int len);


int main(int argc,char* argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */

    if (argc == 1){
        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }
    }
    else{
        dev=argv[1];
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    while (1){
        int retValue;
        /* Grab a packet */
        retValue = pcap_next_ex(handle, &header, &packet);
        if ( retValue < 0 )
            break;
        if ( retValue ==0 )
            continue;
        /* Print its length */
        printf("##########     Total packet length : [%d (0x%x)]     ##########\n", header->len, header->len);
        anal_ethernet(packet);
        printf("\n");
        //        printPacket(packet, header->len);
        /* And close the session */
    }
    pcap_close(handle);
    return 0;
}

void anal_ethernet(const u_char* packet)
{
    struct ether_header *etherHead;
    int i;
    etherHead = (struct ether_header *) packet;
    printf("##########     ETHERNET HEADER     ##########\n");
    printf("Destination MAC address     ");
    for (i=0; i<ETHER_ADDR_LEN;i++)
        printf(":%02x",etherHead->ether_dhost[i]);
    printf("\nSource MAC address          ");
    for (i=0; i<ETHER_ADDR_LEN;i++)
        printf(":%02x",etherHead->ether_shost[i]);
    printf("\n");
    if(ntohs(etherHead->ether_type)==ETHERTYPE_IP)
        anal_ip(packet+ETHER_HDR_LEN);
}

void anal_ip(const u_char *ip_packet)
{
    struct iphdr *ip_head;
    ip_head = (struct iphdr *)ip_packet;
    char src_ip[18],dst_ip[18];
    inet_ntop(AF_INET,&(ip_head->saddr),src_ip,sizeof(src_ip));
    inet_ntop(AF_INET,&(ip_head->daddr),dst_ip,sizeof(dst_ip));

    printf("##########     IP HEADER     ##########\n");
    printf("Source IP address           : %s\n",src_ip);
    printf("Destination IP address      : %s\n",dst_ip);
    printf("Total length                : %d\n",ntohs(ip_head->tot_len));
    printf("Header length               : %d\n",ip_head->ihl*4);
}

void printPacket(u_char* packet,int len)
{
    int i;
    for ( i=0; i < len ; i++ ){
        if (i%16 ==0 && i != 0){
            printf("  ");
            for ( int j=-16;j<=-1;j++ ){
                if (j == -8)
                    printf("  ");
                if (isprint(*(packet+i+j)))
                    printf("%c", *(packet+i+j));
                else
                    printf(".");
            }
            printf("\n");
        }
        if ( i % 8 ==0 )
            printf ("  ");
        printf("%02x ", *(packet+i));
    }
    for(i=0;i<16-(len%16);i++){
        printf("   ");
        if ( i % 8 ==0 )
            printf ("  ");
    }
    for ( int i=(len/16)*16;i<len;i++ ){
        if (i%8 == 0 && i%16 != 0)
            printf("  ");
        if (isprint(*(packet+i)))
            printf("%c", *(packet+i));
        else
            printf(".");
    }
    printf("\n\n");
}

