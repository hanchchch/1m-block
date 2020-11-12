#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <libnet.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define HOSTNAME_MAX_SIZE 64

char host[HOSTNAME_MAX_SIZE];

bool is_ipv4_pkt(u_char* header) {
	libnet_ipv4_hdr* ipv4_hdr = (libnet_ipv4_hdr*)header;
	if((*ipv4_hdr).ip_v != 4) return false;
	if((*ipv4_hdr).ip_hl != 5) return false;
	return true;
}

int locate_host(u_char* data, u_char** out) {
	u_char* payload = data;
	payload += sizeof(libnet_ipv4_hdr);
	payload += sizeof(libnet_tcp_hdr);

	bool host_found = false;
	for (int i=0; i<32; i++) {
		if ((data[i]|0x20) != 'h') continue;
		if ((data[i+1]|0x20) != 'o') continue;
		if ((data[i+2]|0x20) != 's') continue;
		if ((data[i+3]|0x20) != 't') continue;
		host_found = true;
		*out = data+i;
	}
	if (!host_found) return 0;

	char* host_end = strstr(*out, "\r\n");
	if (host_end == NULL) return 0;

	int len = host_end - *out;
	if ((len > HOSTNAME_MAX_SIZE) || (len < 1)) return 0;

	return len;
}

bool is_match_host(u_char* data) {
	char* match = strstr((char*)data, host);

	if (match == NULL) return false;
	return true;
}

static bool check_pkt(struct nfq_data* tb, u_int32_t* id) {
	struct nfqnl_msg_packet_hdr *ph;
	int size;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) *id = ntohl(ph->packet_id);
	
	size = nfq_get_payload(tb, &data);

	if (!is_ipv4_pkt(data)) return false;
	puts("ipv4 packet.");
	
	if (!is_match_host(data)) return false;
	puts("host matched.");

	return true;
}

static int netfilter_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	u_int32_t id;
	int match = check_pkt(nfa, &id);
	
	if (match) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
		puts("syntax : netfilter-test <host>");
		puts("sample : netfilter-test test.gilgil.net");
		exit(EXIT_FAILURE);
	}

	strncpy(host, argv[1], HOSTNAME_MAX_SIZE);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &netfilter_callback, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
