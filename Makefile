CC = gcc
CFLAGS = -Wall -Wextra -Werror -g

# pcap for dnsagent
PCAP_LIBS = -lpcap

all: dnsagent

dnsagent: dnsagent.c
	$(CC) $(CFLAGS) -o dnsagent dnsagent.c $(PCAP_LIBS)

clean:
	rm -f dnsagent *.o

.PHONY: all clean
