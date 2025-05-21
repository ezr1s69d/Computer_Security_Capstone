## 🧪Project 2 - MITM and Pharming Attacks in Wi-Fi Networks

### 🎯GOAL
- Scan IP/MAC addresses of the devices in a Wi-Fi network
- Launch a man-in-the-middle (MITM) attack by using ICMP redirect
- Launch a pharming attack

### 🧨STEP1 - Device Address Information Collection
Collect devices information from arp table, and get ethernet ip address of the victim which is under same wifi network.
```cpp
// The required information can be found in /proc/net/arp
// code is in icmp_redirect.cpp
// example:
// IP address       HW type     Flags       HW address            Mask     Device
// 172.20.128.1     0x1         0x2         00:15:5d:86:1e:78     *        eth0
```

### 🧨STEP2 - ICMP redirect attack
Analyze an ICMP Redirect packet, craft a fake one, and send it to victim. Make the victim believe that sending packets to 8.8.8.8 via the attacker is a better route.
- Analyze ICMP Redirect packet format
  - ICMP Type = 5: indicates Redirect Message
  - Code = 1： Redirect for host
  - Gateway Address：attacker IP
```
ICMP Header (Type 5, Code 1)
1                       16                      32(bits)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|  Type = 5 (Redirect)  |    Code = 1 (Host)    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   Checksum                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|               Gateway IP Address              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

original IP packet
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| victim → 8.8.8.8 的 IP header(first 20 bytes) |
|       ICMP Echo Request(first 8 bytes)        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

```
- Create fake ICMP Redirect packet
  - Use raw socket (SOCK_RAW) transmit self-made IP packet
  - Packet structure：IP Header + ICMP Header + original IP packet (with first 8 bytes)
- 設置 IP_HDRINCL
  - 必須使用 setsockopt() 設定 IP_HDRINCL，以手動控制 IP 標頭

### 🧨STEP3 - DNS Spoofing
Intercept DNS request, analyze the information in the packet, discard it, and send a fake reply back to the victim.
- Intercepts DNS requests using NetfilterQueue
```bash
# Packets to port 53 will be sent to the NFQUEUE numbered 0
# which is configured to be intercepted and processed by our program using the Netfilter Queue (NFQ) library.
system("sudo iptables -F");
system("sudo iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0");
```
- Packets in NFQUEUE will be manipulated in callback function, filter out the packet with destination port 53, and analyze DNS request
```c++
static int cb(struct nfq_q_handle* qh, nfgenmsg* nfmsg,
              nfq_data* nfa, void* data) {
...
}
```
- DNS request format
```
1                       16                      32(bits)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|          ID           |        Flags          |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|        QDCOUNT        |       ANCOUNT         | 
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|        NSCOUNT        |       ARCOUNT         |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 DNS questions                 |
|                      ...                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  DNS answers                  |
|                      ...                      |
```
- DNS packet is udp payload, append it to upd headers
```c++
// tmp[] --> headers, tmp2[] --> DNS quesetions and answers
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
```
