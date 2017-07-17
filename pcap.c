#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>

#define ETHERNET_HEAD_SIZE (14)
#define MAC_ADDR_LEN (6)
#define ETHER_TYPE (2)
#define IP_TYPE (0x0800)

int analEthernet(u_char* packet, struct pcap_pkthdr* header);
int comp(u_char* a, u_long b,int len);
void printPacket(u_char* packet, int len);
void analIpPacket (u_char* ipPacket, int len);
void analTcpPacket ( u_char* tcpPacket, int len);


int main()
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    int i;

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
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    while (1){
        int retValue;
        /* Grab a packet */
        retValue = pcap_next_ex(handle, &header, &packet);

        /* Check empty packet */
        if ( header->len ==0 )
            continue;
        /* Print its length */
        printf("Jacked a packet with length of [%d (0x%x)]\n", header->len, header->len);
        analEthernet(packet,header);

        //        printPacket(packet, header->len);
        /* And close the session */
    }
    pcap_close(handle);
    return 0;
}

int comp(u_char* a, u_long b,int len){
    int i;
    for ( i=0; i < len ; i++){
        if (*(a+i) != ( b/ (int)(pow(256,len-i-1)) ) % 256)
            return -1;
    }
    return 0;
}

int analEthernet(u_char* packet, struct pcap_pkthdr* header)
{
    u_char ethHead[ETHERNET_HEAD_SIZE],etherType[2];
    int i;
    for ( i=0; i < ETHERNET_HEAD_SIZE; i++)
        ethHead[i] = *(packet+i);

    for (i=0; i< ETHER_TYPE ;i++)
        etherType[i]=ethHead[i+(ETHERNET_HEAD_SIZE-ETHER_TYPE)];

    printf("##########     Ethernet Frame Analysis     ##########\n");
    printf("Destination MAC ADDRESS ");
    for ( i=0; i < MAC_ADDR_LEN ; i++)
        printf(":%02x",ethHead[i]);

    printf("\nSource MAC ADDRESS ");
    for ( i=MAC_ADDR_LEN; i< 2*MAC_ADDR_LEN ; i++)
        printf(":%02x",ethHead[i]);
    printf("\n");\

    if (!comp(etherType,IP_TYPE,2)){
        printf("Packet Type : IPv4\n");

        u_char *ipPacket = (u_char*) calloc(header->len - ETHERNET_HEAD_SIZE, sizeof(u_char));
        for ( i =0; i< (header->len - ETHERNET_HEAD_SIZE); i++)
            ipPacket[i] = packet[i+ETHERNET_HEAD_SIZE];
        analIpPacket(ipPacket,header->len - ETHERNET_HEAD_SIZE);

    }
    else
        printf("Unknown packet type\n");
    printf("\n");

    return 0;
}

void analIpPacket (u_char* ipPacket, int len)
{
    int i;
    printf("##########     IP Frame Analysis     ##########\n");
    printf("IP version : %d\n",ipPacket[0]/16);
    printf("IP Header Length : %d\n",ipPacket[0]%16*4);
    printf("Total Length : %d\n",ipPacket[2]*256+ipPacket[3]);
    printf("TTL : %d\n",ipPacket[8]);
    printf("Protocol : %d\n",ipPacket[9]);
    printf("Header Checksum : 0x%x%x (%d)\n",ipPacket[10],ipPacket[11],ipPacket[10]*256+ipPacket[11]);
    printf("Source IP : %d.%d.%d.%d\n",ipPacket[12],ipPacket[13],ipPacket[14],ipPacket[15]);
    printf("Destination IP : %d.%d.%d.%d\n",ipPacket[16],ipPacket[17],ipPacket[18],ipPacket[19]);
    //    printPacket(ipPacket, 20);
    analTcpPacket(ipPacket+ipPacket[0]%16*4,len-ipPacket[0]%16*4);
}

void analTcpPacket(u_char* tcpPacket, int len)
{
    int i;
    printf("##########     TCP Frame Analysis     ##########\n");
    printf("Source Port : %d\n",tcpPacket[0]*256+tcpPacket[1]);
    printf("Destination Port : %d\n",tcpPacket[2]*256+tcpPacket[3]);
    printf("Header Length : %d bytes\n",(tcpPacket[12]/16)*4);
    printf("CheckSum : 0x%02x%02x\n",tcpPacket[16],tcpPacket[17]);
    if (len-(tcpPacket[12]/16)*4 != 0){
<<<<<<< HEAD
        printf("##########     HTML     ##########\n");
=======
        printf("##########     HTML     ##########\n",len-(tcpPacket[12]/16)*4);
>>>>>>> 82a9cac55b4cc3c81845fe7aed1991d516293c00
        printPacket(tcpPacket+(tcpPacket[12]/16)*4,len-(tcpPacket[12]/16)*4);
    }
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
<<<<<<< HEAD
    for ( i=(len/16)*16;i<len;i++ ){
=======
    for ( int i=(len/16)*16;i<len;i++ ){
>>>>>>> 82a9cac55b4cc3c81845fe7aed1991d516293c00
        if (i%8 == 0 && i%16 != 0)
            printf("  ");
        if (isprint(*(packet+i)))
            printf("%c", *(packet+i));
        else
            printf(".");
    }
    printf("\n\n");
}

