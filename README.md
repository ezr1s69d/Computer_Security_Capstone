# Computer Security Capstone Project

---

## 📌 Table of Contents

- [1. Project 1 - TLS Connection Hijacking](./Project1/Readme.md)
- [2. Project 2 - MITM and Pharming Attacks in Wi-Fi Networks](#project-2---mitm-and-pharming-attacks-in-wi-fi-networks)
- [3. Project 3 - Ransomware Propagation and Payload](#project-3---ransomware-propagation-and-payload)
- [4. 測試與觀察結果](#4-測試與觀察結果)

---

## Project 2 - MITM and Pharming Attacks in Wi-Fi Networks

### GOAL
- Scan IP/MAC addresses of the devices in a Wi-Fi network
- Launch a man-in-the-middle (MITM) attack by using ICMP redirect
- Launch a pharming attack

### STEP1 - Device Address Information Collection
Collect devices information from arp table, and get ethernet ip address of the victim which is under same wifi network.
```cpp
// The required information can be found in /proc/net/arp
// code is in icmp_redirect.cpp
// example:
// IP address       HW type     Flags       HW address            Mask     Device
// 172.20.128.1     0x1         0x2         00:15:5d:86:1e:78     *        eth0
```

### STEP2 - ICMP redirect attack
Analyze an ICMP Redirect packet, craft a fake one, and send it to victim. Make the victim believe that sending packets to 8.8.8.8 via the attacker is a better route.

### STEP3 - DNS Spoofing
Intercept DNS request, analyze the information in the packet, discard it, and send a fake reply back to the victim.
- Intercepts DNS requests using NetfilterQueue
```bash
# Packets to port 53 will be sent to the NFQUEUE numbered 0
# which is configured to be intercepted and processed by our program using the Netfilter Queue (NFQ) library.
system("sudo iptables -F");
system("sudo iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0");
```

---

## Project 3 - Ransomware Propagation and Payload

### GOAL
- 
