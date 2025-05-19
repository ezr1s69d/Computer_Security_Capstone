#ifndef UTIL_H
#define UTIL_H

#include <bits/stdc++.h>
#include <cstring>
#include <signal.h>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/if_packet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
using namespace std;

// Network structures
struct eth_hdr {
    uint8_t dest[ETH_ALEN];
    uint8_t src[ETH_ALEN];
    uint16_t ethertype;
};

struct icmp_redirect {
    uint8_t type;       // 5 for redirect
    uint8_t code;       // 0 for network, 1 for host
    uint16_t checksum;
    uint32_t gateway;   // New gateway IP
    struct iphdr original_ip;  // IP header of original packet
    uint8_t original_data[8];  // First 8 bytes of original data
};

struct arphdr {
    uint16_t htype;      // hardware type
    uint16_t ptype;      // protocol type
    uint8_t hlen;        // hardware address length
    uint8_t plen;        // protocol address length
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

struct ip_mac {
    uint8_t ip[4] = {0};
    uint8_t mac[6] = {0};
};

// Helper functions for network addressing
void ip_str_to_bytes(const string &ip_str, uint8_t *ip_bytes);
void print_mac(const uint8_t *mac);
void print_ip(const uint8_t *ip);

// Calculate checksum for network packets
u_int16_t checksum(u_int8_t *buf, int len);

// Signal handler for graceful termination
void signal_handler(int sig);

// Setup and clear iptables rules
void setup_iptables();
void clear_iptables();

// Configure system settings for ICMP redirect
void configure_system_settings();

extern bool running;

#endif // UTIL_H