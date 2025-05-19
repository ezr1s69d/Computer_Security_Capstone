#include "util.h"

bool running = true;

void ip_str_to_bytes(const string &ip_str, uint8_t *ip_bytes) {
    stringstream ss(ip_str);
    string byte;
    int i = 0;
    while (getline(ss, byte, '.')) {
        ip_bytes[i++] = stoi(byte);
    }
}

void print_mac(const uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i != 5)
            printf(":");
    }
}

void print_ip(const uint8_t *ip) {
    for (int i = 0; i < 4; i++) {
        printf("%d", ip[i]);
        if (i != 3)
            printf(".");
    }
}
uint16_t checksum(uint8_t *data, int length) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)data;
    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }
    if (length == 1) {
        sum += *((uint8_t *)ptr);
    }
    // Add carry
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~((uint16_t)sum);
}


void signal_handler(int sig) {
    running = false;
    printf("\n Shutting down...\n");
}

void setup_iptables() {
    system("sudo iptables -F");
    system("sudo iptables -A FORWARD -i enp0s3 -p udp --dport 53 -j NFQUEUE --queue-num 0");
    system("sudo iptables -A INPUT -i enp0s3 -p udp --dport 53 -j NFQUEUE --queue-num 0");
    system("sudo echo 1 > /proc/sys/net/ipv4/ip_forward");
}

void clear_iptables() {
    system("sudo iptables -F");
    system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward");
}

void configure_system_settings() {
    std::string path = "/etc/sysctl.conf";
    std::ofstream file(path);
    if (!file.is_open()) {
        std::cerr << "[!] Failed to open " << path << " (Need sudo?)\n";
        return;
    }

    file << "net.ipv4.conf.all.accept_redirects = 1\n";
    file << "net.ipv4.conf.default.accept_redirects = 1\n";
    file << "net.ipv4.conf.enp0s3.accept_redirects = 1\n";
    file.close();
}