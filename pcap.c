#include <pcap.h>
#include <stdio.h>
#include <ctype.h>

#define ETHERNET_HEAD_SIZE (16)
#define MAC_ADDR_LEN (6)
#define ETHER_TYPE (4)
#define IP_TYPE (0x0800)

void printPacket(u_char*,int);


int main(int argc, char *argv[])
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
    int retValue=0,i;

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
        /* Grab a packet */
        retValue = pcap_next_ex(handle, &header, &packet);
        /* Check empty packet */
        if ( header->len ==0 )
            continue;
        /* Print its length */
        printf("Jacked a packet with length of [%d]\n", header->len);
        printPacket(packet,header->len);
        printf("\n");
        /* And close the session */
    }
    pcap_close(handle);
    return(0);
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
