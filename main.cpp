#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <libnet.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <algorithm>
#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include <sstream>


#define HOSTNAME_MAX_SIZE 64

std::vector<std::string> hostlist;

bool is_ipv4_pkt(u_char* header) {
	libnet_ipv4_hdr* ipv4_hdr = (libnet_ipv4_hdr*)header;
	if((*ipv4_hdr).ip_v != 4) return false;
	if((*ipv4_hdr).ip_hl != 5) return false;
	return true;
}

int locate_host(u_char* data, char* out) {
	data += sizeof(libnet_ipv4_hdr);
	data += sizeof(libnet_tcp_hdr);
	
	char* host_start;
	bool found = false;
	for (int i=0; i<32; i++) {
		if ((data[i]) != 'H') continue;
		if ((data[i+1]) != 'o') continue;
		if ((data[i+2]) != 's') continue;
		if ((data[i+3]) != 't') continue;
		if ((data[i+4]) != ':') continue;
		if ((data[i+5]) != ' ') continue;

		found = true;
		host_start = (char*)data+i+6;
	}
	if (!found) return 0;

	char* host_end;
	int len;

	found = false;
	for (int i=0; i<HOSTNAME_MAX_SIZE; i++) {
		if (host_start[i] != '\r') continue;
		if (host_start[i+1] != '\n') continue;

		found = true;
		host_start[i] = 0;
		host_end = host_start+i;
		len = i;
	}
	if (!found) return 0;
	if ((len > HOSTNAME_MAX_SIZE) || (len < 1)) return 0;
	strncpy(out, host_start, len);
	return len;
}

bool match(std::string a, std::string b) { return (a < b); }
bool comp(std::string a, std::string b) { return (a < b); }

bool binary_search(std::vector<std::string> list, std::string key, int left, int right)
{
    if (left > right) return false;
    int mid = left + (right - left) / 2;
    if (list[mid] == key)
        return true;
    else if (list[mid] < key)
        return binary_search(list, key, mid + 1, right);
    return binary_search(list, key, left, mid - 1);
}

bool check_all_host(u_char* data) {
	char data_host_char[HOSTNAME_MAX_SIZE];
	if (locate_host(data, data_host_char) == 0) return false;

	std::string data_host(data_host_char);
	printf("Host: %s\n", data_host.c_str());

	bool match = binary_search(hostlist, data_host, 0, hostlist.size()-1);
	if (match) return true;
	else return false;
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
	if (!check_all_host(data)) return false;
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
		puts("syntax : 1m-block <site list file>");
		puts("sample : 1m-block top-1m.txt");
		exit(EXIT_FAILURE);
	}

	std::string line;
	std::ifstream ifs;
	ifs.open(argv[1]);

	for (;!ifs.eof(); std::getline(ifs, line, '\n')) {
		std::string host = line.substr(line.find(',')+1);
		hostlist.push_back(host);
	}
	std::sort(hostlist.begin(), hostlist.end(), comp);

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
