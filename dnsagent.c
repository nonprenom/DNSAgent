#define _DEFAULT_SOURCE // to enable pcap definition of u_char below

#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <ctype.h>

#include <pcap.h>
#include <net/ethernet.h> // struct ether_header
#include <netinet/ip.h>	  // struct iphdr
#include <netinet/udp.h>  // struct udphdr
#include <netinet/tcp.h>  // struct tcphdr
#include <arpa/nameser.h>

// functions prototypes
static void *dns_responses_agent(void *arg);														   // the main thread
static void dns_response_parser(u_char *args, const struct pcap_pkthdr *header, const u_char *packet); // callback of pcap_loop
static int dns_names_parser(const uint8_t *dns_data, size_t offset, char *name);					   // to parse the strings in the dns answers

/**
 * @brief entry point
 *
 * @param argc : number of arguments (1 + 1)
 * @param argv :[0] : command
 * 				[1] : the network interface
 * @return success(0) / failure(1)
 */
int main(int argc, char **argv)
{
	// get the interface to listen to eth0, wlan0, etc.. (use "ip a" to list them)
	if (argc != 2)
	{
		printf("Usage: %s <interface>\n", argv[0]);
		return EXIT_FAILURE;
	}

	// the pcap_loop() is blocking until the program exit, closes the pacp handler or a fatal system error happend.
	// in case this feature will be use as part of a bigger application, let's run it inside a specific thread.
	pthread_t th;

	/* Pass the interface to use */
	if (pthread_create(&th, NULL, dns_responses_agent, argv[1]) != 0)
	{
		perror("pthread_create");
		return EXIT_FAILURE;
	}

	/* Wait for thread to finish */
	pthread_join(th, NULL);

	return EXIT_SUCCESS;
}

/**
 * @brief Configure and start the pcap filtering loop on the interface specified in parameter.
 *
 * @param arg : c-string with the name of the interface to use
 * @return void*
 */

// Define the desired buffer size (e.g., 4 MiB)
#define CAPTURE_BUFFER_SIZE (4 * 1024 * 1024)

static void *dns_responses_agent(void *arg)
{
	char *interface = (char *)arg;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int ret;

	printf("Initialization of DNS Agent on interface [%s]\n", interface);

	// create the pcap handle
	handle = pcap_create(interface, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "pcap_create failed: %s\n", errbuf);
		return NULL;
	}

	// configure the buffer size (there was lots of truncated packets when calling "dig" very fast)
	printf("Setting kernel buffer size to %d bytes...\n", CAPTURE_BUFFER_SIZE);
	ret = pcap_set_buffer_size(handle, CAPTURE_BUFFER_SIZE);
	if (ret < 0)
	{
		fprintf(stderr, "pcap_set_buffer_size failed: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return NULL;
	}
	pcap_set_snaplen(handle, 65535); // Snapshot length (snaplen)
	pcap_set_promisc(handle, 1);	 // Promiscuous mode
	pcap_set_timeout(handle, 1000);	 // Read timeout (1000 ms)

	// activatepcap
	ret = pcap_activate(handle);
	if (ret < 0)
	{
		fprintf(stderr, "pcap_activate failed: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		return NULL;
	}

	/* capture DNS responses only */
	struct bpf_program fp;
	// const char *filter = "udp and src port 53"; -> this doesn' t capture the "big" TCP DNS responses
	const char *filter = "udp and src port 53 or tcp and src port 53";

	if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Failed to set PCAP filter\n");
		pcap_close(handle);
		return NULL;
	}

	printf("Listening for DNS responses (%s) on %s...\n", filter, interface);

	pcap_loop(handle, -1, dns_response_parser, NULL);

	pcap_close(handle);

	return NULL;
}

/* pcap callback */
static void dns_response_parser(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	args = args; // it's the last arg passed to pcap_loop (NULL here)
	// The packet we want have this format : [Ethernet header][IP header][UDP/TCP header][DNS header]
	// Even if a filter was specified it's better to check if it's the one expected
	// if the value is 2 bytes, we need to use ntohs to convert from the network byte order to the host byte order (endianess)

	// [Ethernet header] Check the ethernet ID (type) is IP
	if (header->caplen < sizeof(struct ether_header))
	{
		// Packet too short for Ethernet header
		return;
	}
	const struct ether_header *eth = (const struct ether_header *)packet;
	uint16_t etherType = ntohs(eth->ether_type);
	if (etherType != ETHERTYPE_IP)
	{
		return;
	}

	if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
	{
		// too short for IP header
		return;
	}

	// [IP header]
	const struct iphdr *ip = (const struct iphdr *)(packet + ETHER_HDR_LEN);
	// note : the length of the IP header is not sizeof(struct iphdr).
	//		  it is variable. the corrct length is 4 bytes * ihl value
	//		https://datatracker.ietf.org/doc/html/rfc791#section-3.1
	const uint8_t ip_hdr_len = ip->ihl * 4;
	if (ip_hdr_len < 20)
	{
		// Invalid IP header length
		return;
	}
	// when the answer to the dns query is small, we receive a udp packet
	// when the answer is big (like a query with all the records = ANY), we get a TCP packet. the DNS header is 2 bytes after the TCP header.
	uint8_t proto_hdr_size = 0;
	if (ip->protocol == IPPROTO_TCP)
	{
		if (header->caplen < ETHER_HDR_LEN + ip_hdr_len + sizeof(struct tcphdr))
		{
			// too short for TCP header
			return;
		}
		const struct tcphdr *tcp = (const struct tcphdr *)(packet + ETHER_HDR_LEN + ip_hdr_len);
		proto_hdr_size = tcp->th_off * 4 + 2;
	}
	else
	{
		proto_hdr_size = sizeof(struct udphdr);
	}

	// parse the packet
	// I took the definition here : https://www.geeksforgeeks.org/computer-networks/dns-message-format/
	const struct dnshdr
	{
		uint16_t id; // Identification
		uint16_t flags;
		uint16_t nbQuestions;	// Number of questions
		uint16_t nbAnswers;		// Number of answers records
		uint16_t nbAuthorities; // Number of authorities records
		uint16_t nbAdditionals; // Number of additionals record
	} __attribute__((packed)) *dns = (struct dnshdr *)(packet + ETHER_HDR_LEN + ip_hdr_len + proto_hdr_size);
	if (header->caplen < ETHER_HDR_LEN + ip_hdr_len + proto_hdr_size + sizeof(struct dnshdr))
	{
		// too short for DNS header
		return;
	}

	// Check if it's an answer and not a query (flags.QR = 1), if there is answer(s) and if it's not an UDP truncated
	const struct dnshdr_flags // this is the network order
	{
		uint8_t QR : 1;
		uint8_t Opcode : 4;
		uint8_t AA : 1;
		uint8_t TC : 1;
		uint8_t RD : 1;
		uint8_t RA : 1;
		uint8_t zero : 3;
		uint8_t rCode : 4;
	} *flags = (struct dnshdr_flags *)&dns->flags;
	if (flags->QR == 0 /* Query */ || ntohs(dns->nbAnswers) == 0 || flags->TC == 1 /* truncated */)
	{
		return;
	}

	/* Parse the DNS data:
	   There are 4 sections:
	   - the question
	   - the answer
	   - the authority
	   - additionals
	   we need to parse the answer.
	   to get the the answer we need to read the question.*/

	/* Parse the question section.
		the resolved name : variable length ended with 0
		type (2 bytes)
		class (2 bytes)

		there are header->nbQuestions triplets
	*/

	/* parse the name
		names are splitted around the "." character and each part is encoded as length(1 byte)-value pairs
		www.google.com -> 3www6google3com\0
		there is some kind of compression/optimization to avoid repeating the same string (similar to the ELF format a bit)
		if the length have a specific value, it means it's a pointer to an existing string in the answer buffer.
	*/
	char name[512];
	memset(name, 0, sizeof(name));
	uint8_t *dns_data = (uint8_t *)dns;	   // to access the data bytes per bytes.
	size_t offset = sizeof(struct dnshdr); // point to the beginning of the data

	for (int i = 0; i < ntohs(dns->nbQuestions); i++)
	{
		memset(name, 0, sizeof(name));
		offset = dns_names_parser(dns_data, offset, name);
		offset += 4; // skip type + class
	}
	offset++;

	// offset is now at the Answer section
	for (int i = 0; i < ntohs(dns->nbAnswers); i++)
	{
		memset(name, 0, sizeof(name));
		offset = dns_names_parser(dns_data, offset, name);

		struct dns_answer_row
		{
			uint16_t type;
			uint16_t class;
			uint32_t ttl;
			uint16_t data_length;
		} __attribute__((packed)) *answer_row = (struct dns_answer_row *)&dns_data[offset];
		offset += sizeof(struct dns_answer_row);
		uint16_t data_length = ntohs(answer_row->data_length);
		uint16_t type = ntohs(answer_row->type);

		if (type == T_A || type == T_AAAA || type == T_CNAME)
		{
			if (i == 0)
			{
				// print a small header for this record
				struct tm *local_time = localtime(&header->ts.tv_sec);
				char local_time_s[128];
				strftime(local_time_s, sizeof(local_time_s) - 1, "%Y-%m-%d %H:%M:%S", local_time);
				printf("[%s][%s]", local_time_s, (ip->protocol == IPPROTO_TCP) ? "TCP" : "UDP");
			}
			printf("\n\t[%s]", name); // resolved name

			switch (type)
			{
			case T_A: // IP v4
				printf("[A:%d.%d.%d.%d]", dns_data[offset], dns_data[offset + 1], dns_data[offset + 2], dns_data[offset + 3]);
				break;

			case T_AAAA: // IP v6
			{
				char ipv6_str[INET6_ADDRSTRLEN];
				if (inet_ntop(AF_INET6, &dns_data[offset], ipv6_str, INET6_ADDRSTRLEN) != NULL)
				{
					printf("[AAAA:%s]", ipv6_str);
				}
				break;
			}

			case T_CNAME: // CNAME
				dns_names_parser(dns_data, offset, name);
				printf("[CNAME:%s]", name);
				break;

			default:
				break;
			}
		}

		offset += data_length;
	}
	printf("\n");
}

static int dns_names_parser(const uint8_t *dns_data, size_t offset, char *name)
{
	uint8_t len = dns_data[offset];
	if (len == 0)
	{
		return offset + 1;
	}

	if (len < 0xC0) // standard len + label
	{
		int curr_len = strlen(name);
		if (curr_len > 0)
		{
			name[curr_len] = '.';
			curr_len++;
		}
		offset++;
		if (curr_len + len < 512)
		{
			memcpy(name + curr_len, &dns_data[offset], len);
			name[curr_len + len] = 0;
		}
		offset += len;
		if (dns_data[offset] != 0)
		{
			// this label does not close the string yet, continue to concatenate the next one
			offset = dns_names_parser(dns_data, offset, name);
		}
	}
	else // Compressed name -> it's a pointer to a string in the buffer.
	{
		// the first 2 bits are 11 (C0 = 1100) and the 14 next bits is the offset inside the dns answer (from the header) where the full name is located
		// need to combine both of them (b1 * 256 + b2) and clear the first 2 bits with a bit mask (0011111111111111 = 0x3FFF).
		size_t offset_value = (dns_data[offset] * 256 + dns_data[offset + 1]) & 0x3FFF;
		dns_names_parser(dns_data, offset_value, name);
		offset += 2; // 16 bits
	}
	return offset;
}
