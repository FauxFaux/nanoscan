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

static uint32_t min(uint32_t a, uint32_t b) {
	return a < b ? a : b;
}

static unsigned short csum(unsigned short *ptr, int nbytes) {
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
static uint32_t source_ip;

static uint32_t generate_source_ip() {
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

int main(int argc, char *argv[]) {

	if (argc != 3) {
		printf("usage: %s start-ip end-ip\n", argv[0]);
		return 7;
	}

	struct in_addr from, to;
	if (1 != inet_pton(AF_INET, argv[1], &from) || 1 != inet_pton(AF_INET, argv[2], &to)) {
		printf("source or dest ip not valid\n");
		return 8;
	}

	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (-1 == s) {
		printf("can't open raw socket; are you root?\n");
		return 4;
	}

	const int one = 1;
	const int *val = &one;
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		return 5;
	}

	srand(time(NULL) ^ source_ip ^ getpid());

	const uint32_t fromi = ntohl(from.s_addr);
	const uint32_t toi = ntohl(to.s_addr);
	const uint32_t range = toi - fromi;

	const uint32_t min_shuffle = min(512, range);
	const uint32_t max_shuffle = min(32768, range);

	uint32_t i;
	const uint32_t step = rand() % (max_shuffle - min_shuffle) + min_shuffle;
	unsigned short pos[max_shuffle];

	for (i = 0; i < step; ++i)
		pos[i] = i;

	for (i = step - 1; i > 1; --i) {
		size_t j = rand() % i;
		unsigned short t = pos[j];
		pos[j] = pos[i];
		pos[i] = t;
	}

	uint32_t j;
	for (j = 0; j < step; ++j)
		for (i = fromi + pos[j]; i <= toi; i += step) {
			char datagram[4096] = {};
			memset(datagram, 0, 4096);
			short target_port = 443;
			short src_port = 61322;
			struct iphdr *iph = (struct iphdr *) datagram;
			struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
			struct sockaddr_in sin = {};
			source_ip = generate_source_ip();

			struct pseudo_header psh = {};

			sin.sin_family = AF_INET;
			sin.sin_port = htons(target_port);
			sin.sin_addr.s_addr = htonl(i);

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

			char buf[SOME];
			if (sendto(s,
						datagram,
						iph->tot_len,
						0,
						(struct sockaddr *) &sin,
						sizeof (sin)) < 0) {
				int target = htonl(i);
				printf ("error sending %s\n", inet_ntop(AF_INET, &target, buf, SOME));
				return 6;
			}
		}

	return 0;
}

