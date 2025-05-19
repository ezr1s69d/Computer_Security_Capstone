CC = g++
CFLAGS = -Wall -std=c++11 -pthread
LDFLAGS = -lnetfilter_queue

# Targets
all: icmp_redirect pharm_attack

icmp_redirect: icmp_redirect.cpp util.cpp util.h
	$(CC) $(CFLAGS) -o $@ icmp_redirect.cpp util.cpp

pharm_attack: pharm_attack.cpp util.cpp util.h
	$(CC) $(CFLAGS) -o $@ pharm_attack.cpp $(LDFLAGS)

# Clean up
clean:
	rm -f icmp_redirect pharm_attack

.PHONY: all clean

