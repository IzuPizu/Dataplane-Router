#include "lib.h"
#include "protocols.h"
#include "queue.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ROUTE_ENTRIES 100000
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define MAC_SIZE 6
#define ICMP_PROTOCOL 1

struct route_table_entry *find_in_routetable(uint32_t ip_dest, int left, int right);
struct arp_table_entry *get_arp_entry(uint32_t given_ip, int arp_table_len);
int comparator_route_table(const void *a, const void *b);
int comparator_arp_table(const void *a, const void *b);
void setIPdata(struct iphdr *ip_hdr);
void setICMPdata(struct icmphdr *icmp_hdr, uint8_t type);
void setETHdata(struct ether_header *eth_hdr, int interface);
void send_icmp_message(uint8_t type, char *buffer, int interface);
void sendIPv4(char *buffer, int len, int interface, int route_table_len, int arp_table_len);
bool check_checksum(struct iphdr *ip_header);

// define route table
struct route_table_entry *route_table;
// define arp table
struct arp_table_entry *arp_table;

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	// Do not modify this line
	init(argc - 2, argv + 2);

	// Allocate memory for routing table & arp table
	route_table = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);
	arp_table = (struct arp_table_entry *)malloc(sizeof(struct arp_table_entry) * 10);
	int route_table_len = read_rtable(argv[1], route_table);
	int arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	DIE(route_table == NULL, "memory for route table");
	FILE *fptr = fopen(argv[1], "r");
	DIE(fptr == NULL, "could not open file");
	DIE(arp_table == NULL, "memory for arp table");

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// Get ethernet header from packet buffer
		struct ether_header *eth_hdr = (struct ether_header *)buf;

		// Sort the tables
		qsort((void *)route_table, route_table_len, sizeof(struct route_table_entry), comparator_route_table);
		qsort((void *)arp_table, arp_table_len, sizeof(struct arp_table_entry), comparator_arp_table);

		// Check if the packet is valid : MAC dest = MAC interface(on which the packet was received) OR MAC dest =
		// broadcast Get MAC interface in mac_interface variable
		uint8_t *mac_interface = (uint8_t *)malloc(MAC_SIZE);
		get_interface_mac(interface, mac_interface);
		uint8_t *mac_broadcast = (uint8_t *)malloc(MAC_SIZE);
		memcpy(mac_broadcast, "/xFF/xFF/xFF/xFF/xFF/xFF", MAC_SIZE);

		int retc1 = memcmp(mac_interface, eth_hdr->ether_dhost, MAC_SIZE);
		int retc2 = memcmp(mac_broadcast, eth_hdr->ether_dhost, MAC_SIZE);
		if (retc1 != 0 && retc2 != 0) {
			continue; // drop the packet
		}

		// Check the packet type
		uint16_t ether_type = ntohs(eth_hdr->ether_type);
		if (ether_type != ETH_P_IP && ether_type != ETH_P_ARP) {
			continue; // Ignore the packet if is not IP or ARP
		}

		// IPv4 Packet
		if (ether_type == ETH_P_IP) {
			sendIPv4(buf, len, interface, route_table_len, arp_table_len);
			continue;
		}

		// ARP Packet
		if (ether_type == ETH_P_ARP) {
			continue;
		}

		// Free the memory
		free(mac_interface);
		free(mac_broadcast);
	}
	// Free the memory
	free(route_table);
	free(arp_table);
	fclose(fptr);
}

struct route_table_entry *find_in_routetable(uint32_t ip_dest, int left, int right)
{
	// LPM Alghoritm using Binary Search
	struct route_table_entry *entry = NULL;
	while (right >= left) {
		int mid = left + (right - left) / 2;

		if ((route_table[mid].prefix & route_table[mid].mask) == (ip_dest & route_table[mid].mask))
			entry = &route_table[mid];

		if ((route_table[mid].prefix & route_table[mid].mask) > (ip_dest & route_table[mid].mask))
			right = mid - 1;

		else
			left = mid + 1;
	}

	return entry;
}

int comparator_route_table(const void *a, const void *b)
{
	// Compare by (prefix & mask)
	uint32_t prefix_and_mask_a = (((struct route_table_entry *)a)->prefix & ((struct route_table_entry *)a)->mask);
	uint32_t prefix_and_mask_b = (((struct route_table_entry *)b)->prefix & ((struct route_table_entry *)b)->mask);

	if (prefix_and_mask_a == prefix_and_mask_b)
		if (((struct route_table_entry *)a)->mask > ((struct route_table_entry *)b)->mask)
			return 1;
		else if (((struct route_table_entry *)a)->mask < ((struct route_table_entry *)b)->mask)
			return -1;
		else
			return 0;

	else if (prefix_and_mask_a > prefix_and_mask_b)
		return 1;
	else
		return -1;
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip, int arp_table_len)
{
	int left = 0;
	int right = arp_table_len - 1;

	while (left <= right) {
		int mid = left + (right - left) / 2;

		if (arp_table[mid].ip == given_ip)
			return &arp_table[mid];

		if (arp_table[mid].ip < given_ip)
			left = mid + 1;
		else
			right = mid - 1;
	}

	// If given_ip is not found in the arp_table
	return NULL;
}

void setIPdata(struct iphdr *ip_hdr)
{
	// Set the IP header data
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->frag_off = 0;
	ip_hdr->version = 4;
	ip_hdr->protocol = ICMP_PROTOCOL;
	ip_hdr->ihl = 5;
	ip_hdr->id = 1;

	// Swap  source and destination IP addresses because router is sending the packet to host
	uint32_t sourceIP = ip_hdr->saddr;
	uint32_t destinationIP = ip_hdr->daddr;
	// source IP -> destination IP
	ip_hdr->saddr = destinationIP;
	// destination IP -> source IP
	ip_hdr->daddr = sourceIP;
}

void setICMPdata(struct icmphdr *icmp_hdr, uint8_t type)
{
	// Set ICMP header data
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
}

void setETHdata(struct ether_header *eth_hdr, int interface)
{
	// Set ETHERNET header data
	//  Get interface the packet was received from in router
	uint8_t *mac_interface = (uint8_t *)malloc(MAC_SIZE);
	get_interface_mac(interface, mac_interface);
	// Swap source and destination MAC addresses => destination MAC -> source MAC
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_SIZE);
	// source MAC -> destination MAC (because router is now sending the packet to emitter)
	memcpy(eth_hdr->ether_shost, mac_interface, MAC_SIZE);
}

void send_icmp_message(uint8_t type, char *buffer, int interface)
{
	// Get ICMP header
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
	// Get ethernet header
	struct ether_header *eth_hdr = (struct ether_header *)buffer;
	// Get IP header
	struct iphdr *ip_hdr = (struct iphdr *)(buffer + sizeof(struct ether_header));

	// Set ICMP header data
	setICMPdata(icmp_hdr, type);
	// Set IP header data
	setIPdata(ip_hdr);
	// Set ETHERNET header data
	setETHdata(eth_hdr, interface);

	// Send the message with the new data
	size_t new_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	send_to_link(interface, (char *)buffer, new_len);
}

int comparator_arp_table(const void *e1, const void *e2)
{
	// Used for sorting the arp_table based on IP for efficency
	struct arp_table_entry *elem2 = (struct arp_table_entry *)e2;
	struct arp_table_entry *elem1 = (struct arp_table_entry *)e1;

	if (elem1->ip > elem2->ip) {
		return 1;
	} else if (elem1->ip > elem2->ip) {
		return -1;
	}
	return 0;
}

bool check_checksum(struct iphdr *ip_header)
{
	// Compute new checksum and verify integrity of the packet  (new checksum must be the same with previous one)
	uint16_t old_checksum = ntohs(ip_header->check);
	ip_header->check = 0;
	uint16_t new_checksum = 0;
	new_checksum = checksum((uint16_t *)ip_header, sizeof(struct iphdr));
	if (ntohs(old_checksum) == ntohs(new_checksum))
		return true;
	else
		return false;
}

void sendIPv4(char *buf, int len, int interface, int route_table_len, int arp_table_len)
{
	// Get the IP header
	struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
	if (check_checksum(ip_header) == false)
		return;
	// Verify TTL
	if (ip_header->ttl <= 1) {
		// send "Time exceeded" ICMP message back to emitter
		send_icmp_message(11, buf, interface);
		// drop the packet if TTL is 0 or 1
		return;
	}
	// Decrement the TTL to avoid loops
	ip_header->ttl--;
	// Update the checksum after TTL has been changed
	ip_header->check = 0;
	ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));

	if (ip_header->daddr == inet_addr(get_interface_ip(interface))) {
		// Router received "Echo request" => We need to "echo reply"
		send_icmp_message(0, buf, interface);
		return;
	}

	// Find the IP destination in routing table to determine next_hop and the output interface
	struct route_table_entry *best_route = find_in_routetable(ip_header->daddr, 0, route_table_len);
	// If route has been found
	if (best_route != NULL) {
		struct ether_header *eth_hdr = (struct ether_header *)buf;
		// Overwrite source & dest MAC addresses
		struct arp_table_entry *entry_arp = get_arp_entry(best_route->next_hop, arp_table_len);
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		// update destination mac
		memcpy(eth_hdr->ether_dhost, entry_arp->mac, sizeof(uint8_t) * MAC_SIZE);
		// send packet to next hop
		send_to_link(best_route->interface, buf, len);
	} else {
		// Send "Destination Unreacheable" icmp message
		send_icmp_message(3, buf, interface);
		// If we did not find anything => drop the packet
		return;
	}
}
