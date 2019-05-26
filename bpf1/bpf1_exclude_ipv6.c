#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <netpacket/packet.h>
#include <net/if.h>

#include <errno.h>

int main(){
    int soc;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    unsigned char buf[4096];

    memset(&ifr, 0, sizeof(ifr));
    memset(&sll, 0, sizeof(sll));

    if ((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    	perror("socket");
    }

    strncpy(ifr.ifr_name, "br0", IFNAMSIZ);
    if ((ioctl(soc, SIOCGIFINDEX, &ifr)) == -1) {
    	perror("ioctl");
    }

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(soc, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
	    perror("bind");
    }

    while(1){
        ssize_t len = recv(soc, buf, sizeof(buf), 0);
        struct ethhdr* ethhdr = (struct ethhdr*)buf;
        int proto = ntohs(ethhdr->h_proto);
        if(len <= 0) break;
	else if (proto==ETH_P_IPV6) continue;
        printf("%3ld %0x %s\n", len, proto,
                proto==ETH_P_ARP ? "arp" : proto==ETH_P_IP ? "ip" : proto==ETH_P_IPV6 ? "ipv6" : "other");
    }
    return 0;
}
