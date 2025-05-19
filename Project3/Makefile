CC = gcc
CFLAGS = -O2 -Wall
TARGETS = infected_echo attack_server aes-tool

all: $(TARGETS)

infected_echo: wrapper.c
	$(CC) $(CFLAGS) -DATTACKER_IP=\"$(ATTACKER_IP)\" -DPORT=\"$(PORT)\" $^ -o $@ -lz

attack_server: attack_server.c
	$(CC) $(CFLAGS) $^ -o $@

aes-tool: aes-tool.c
	$(CC) $(CFLAGS) $^ -o $@ -lssl -lcrypto

clean:
	rm -f $(TARGETS)

