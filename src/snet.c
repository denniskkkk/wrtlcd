#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <errno.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/route.h>

int set_ip(char *iface_name, char *ip_addr, short prefix, char* ip_broadcast ) {
	if (!iface_name)
		return -1;

	int sockfd;
	struct ifreq ifr;
	struct sockaddr_in sin;
	struct sockaddr_in mask;
	struct sockaddr_in broadcast;
	short flag;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		fprintf(stderr, "Could not get socket.\n");
		return -1;
	}

	/* get interface name */
	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
	/* Read interface flags */
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "ifdown: shutdown\n ");
		perror(ifr.ifr_name);
		return -1;
	}

	/*
	 * Expected in <net/if.h> according to
	 * "UNIX Network Programming".
	 */
#ifdef ifr_flags
# define IRFFLAGS       ifr_flags
#else   /* Present on kFreeBSD */
# define IRFFLAGS       ifr_flagshigh
#endif

	// If interface is down, bring it up
	if (ifr.IRFFLAGS | ~(IFF_UP)) {
		fprintf(stdout, "Device is currently down..setting up.-- %u\n",
				ifr.IRFFLAGS);
		ifr.IRFFLAGS |= IFF_UP;
		if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
			fprintf(stderr, "ifup: failed ");
			perror(ifr.ifr_name);
			return -1;
		}
	}

	printf("-promisc\n");
    flag = IFF_PROMISC;
	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "get promisc : failed ");
		return -1;
	}
	ifr.ifr_flags &= ~flag;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "clear promisc: failed ");
		return -1;
	}

	printf("+MultiCAST\n");
	flag = IFF_MULTICAST | IFF_BROADCAST;
	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "get multicast: failed ");
		return -1;
	}
	ifr.ifr_flags |= flag;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "set mulitcast: failed ");
		perror(ifr.ifr_name);
		return -1;
	}

	printf("set ip\n");
	memset(&sin, 0, sizeof(struct sockaddr));
	sin.sin_family = AF_INET;
	// Convert IP from numbers and dots to binary notation
	inet_aton(ip_addr, &sin.sin_addr.s_addr);
	memcpy((char *) &ifr.ifr_addr, (char*) &sin, sizeof(struct sockaddr));
	if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
		fprintf(stderr, "Cannot set IP address. ");
		perror(ifr.ifr_name);
		return -1;
	}
// set netmask//
	memset(&mask, 0, sizeof(struct sockaddr));
	mask.sin_addr.s_addr = htonl(~(0xffffffffU >> prefix)); // subnet mask//
	mask.sin_family = AF_INET;
	memcpy((char *) &ifr.ifr_netmask, (char *) &mask, sizeof(struct sockaddr));
	printf("set mask\n");
	if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
		fprintf(stderr, "Cannot set mask prefix. ");
		perror(ifr.ifr_name);
		return -1;
	}

	// set broadcast address
	printf ("set broadcast\n");
	memset (&broadcast,0, sizeof (struct sockaddr));
	broadcast.sin_family = AF_INET;
	inet_aton(ip_broadcast, &broadcast.sin_addr.s_addr);
    memcpy((char*)&ifr.ifr_addr, (char*) &broadcast, sizeof (struct sockaddr));
    if (ioctl(sockfd, SIOCSIFBRDADDR, &ifr ) < 0 ) {
		fprintf(stderr, "Cannot set broadcast address. ");
		perror(ifr.ifr_name);
		return -1;
    }


#undef IRFFLAGS
}
void setRoute() {
	int sockfd;
	struct sockaddr_in *addr;
	struct rtentry route;
	memset(&route, 0, sizeof(route));
	addr = (struct sockaddr_in*) &route.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr("192.168.1.1");
	addr = (struct sockaddr_in*) &route.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr("0.0.0.0");
	addr = (struct sockaddr_in*) &route.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr("0.0.0.0");
	route.rt_flags = RTF_UP | RTF_GATEWAY;
	route.rt_metric = 0;
	if (ioctl(sockfd, SIOCADDRT, &route) != 0) {
		fprintf(stderr, "Route set fail");
		return;
	}

	return;
}

int setMacAddress(char *ifname, char *addr) {
	int sockfd;
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_addr.sa_family = AF_UNIX;
	memcpy(ifr.ifr_hwaddr.sa_data, addr, 6);
	if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "set HWADDR\n");
		return -1;
	}
	//shutdown(sock, SHUT_RDWR);
	return 0;
}



