#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

unsigned short csum(unsigned short *ptr, int nbytes) {
	long sum = 0;
	unsigned short oddbyte;

	while (nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}

	if (nbytes==1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum>>16) + (sum & 0xffff);
	sum = sum + (sum>>16);
	return (unsigned short)~sum;
}

const size_t SOME = 256;
uint32_t source_ip;

uint32_t generate_source_ip() {
	char buf[SOME];
	if (gethostname(buf, SOME)) {
		printf("couldn't get local hostname\n");
		exit(1);
	}

	struct addrinfo hints = {}, *info;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	if (0 != getaddrinfo(buf, NULL, &hints, &info)) {
		printf("couldn't resolve local hostname\n");
		exit(2);
	}

	
	if (NULL != info->ai_next) {
		printf("didn't find exactly one address for the local hostname\n");
		exit(3);
	}

	return ((struct sockaddr_in *)info->ai_addr)->sin_addr.s_addr;
}

int main() {
	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (-1 == s) {
		printf("can't open raw socket; are you root?\n");
		return 4;
	}

	const int one = 1;
	const int *val = &one;
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(5);
	}

	char datagram[4096] = {};
	memset(datagram, 0, 4096);
	short target_port = 443;
	short src_port = 61322;
	struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin = {};
	source_ip = generate_source_ip();

	srand(time(NULL) ^ source_ip ^ getpid());


	struct pseudo_header psh = {};

	sin.sin_family = AF_INET;
	sin.sin_port = htons(target_port);
	sin.sin_addr.s_addr = inet_addr ("137.205.210.240");

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htonl(0);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = source_ip;
	iph->daddr = sin.sin_addr.s_addr;
	iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

	tcph->source = htons(src_port);
	tcph->dest = htons(target_port);
	tcph->doff = 5;
	tcph->syn = 1;
	tcph->window = htons(5840);

	psh.source_address = source_ip;
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(20);

	memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
	tcph->check = csum((unsigned short*) &psh , sizeof(struct pseudo_header));

	if (sendto(s,
				datagram,
				iph->tot_len,
				0,
				(struct sockaddr *) &sin,
				sizeof (sin)) < 0) {
		printf ("error sending\n");
		exit(6);
	}

	return 0;
}

