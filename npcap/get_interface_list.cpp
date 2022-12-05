#include <iostream>
#include <winsock2.h>
#include "pcap.h"

#define ADDR_STR_MAX 128
const char* iptos(struct sockaddr *sockaddr)
{
    static char address[ADDR_STR_MAX] = {0};
    int gni_error = 0;

    gni_error = getnameinfo(sockaddr,
        sizeof(struct sockaddr_storage),
        address,
        ADDR_STR_MAX,
        NULL,
        0,
        NI_NUMERICHOST);
    if (gni_error != 0)
    {
    fprintf(stderr, "getnameinfo: %s\n", gai_strerror(gni_error));
    return "ERROR!";
    }

    return address;
}

void ifprint(pcap_if_t *d)
{
    pcap_addr_t *a;
    char ip6str[128];

    /* Name */
    printf("%s\n",d->name);

    /* Description */
    if (d->description)
    printf("\tDescription: %s\n",d->description);

    /* Loopback Address*/
    printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

    /* IP addresses */
    for(a=d->addresses;a;a=a->next)
    {
        printf("\tAddress Family: #%d\n",a->addr->sa_family);

        switch(a->addr->sa_family)
        {
            case AF_INET:
            printf("\tAddress Family Name: AF_INET\n");
            if (a->addr)
                printf("\tAddress: %s\n", inet_ntoa(((sockaddr_in *)a->addr)->sin_addr));
            // if (a->netmask)
            //     printf("\tNetmask: %s\n", inet_ntoa(a->netmask));
            // if (a->broadaddr)
            //     printf("\tBroadcast Address: %s\n", iptos(a->broadaddr));
            // if (a->dstaddr)
            //     printf("\tDestination Address: %s\n", iptos(a->dstaddr));
            break;


            default:
                printf("\tAddress Family Name: Unknown\n");
            break;
        }
    }
    printf("\n");
}

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for(d = alldevs; d != NULL; d = d->next)
    {
        ifprint(d);
        switch(a->addr->sa_family)
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
}