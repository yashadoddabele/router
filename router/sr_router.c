/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/* SR_HANDLEPACKET */
/* Incoming packet goes here and is determined to be IP or ARP. */
/* Packet forwarded to handle_x_type method. */

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  printf("*** -> Received packet of length %d \n",len);

  if (len < sizeof(sr_ethernet_hdr_t)) {
  	  printf("Incoming packet too small\n");
  	  return;
  }
  print_hdrs(packet, len);
  switch (ethertype(packet)) {
  case ethertype_arp:
    printf("Handling ARP packet\n");
  	handle_arp_packet(sr, packet + sizeof(sr_ethernet_hdr_t), interface, len - sizeof(sr_ethernet_hdr_t));
  	break;
  case ethertype_ip:
    printf("Handling IP packet\n");
    handle_ip_packet(sr, packet, len, interface);
  default:
  	printf("Packet received is unknown: dropping packet.\n");
  	return;
  } 
}

void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    sr_ip_hdr_t* ip_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    unsigned int ip_len = len - sizeof(sr_ethernet_hdr_t);
    printf("First headers");
    print_hdrs(packet, len);

    /* Check length */
    if (ip_len < sizeof(sr_ip_hdr_t)) {
        printf("Packet too small\n");
        return;
    }

    uint16_t incoming_cksm = ntohs(ip_packet->ip_sum);
    ip_packet->ip_sum = 0; 
    uint16_t calc_cksm = ntohs(cksum(ip_packet, sizeof(sr_ip_hdr_t)));

    /* Validate checksum */
    if (incoming_cksm != calc_cksm) {
        printf("Invalid checksum.\n");
        return;
    }

    /* Check if TTL is out */
    if (ip_packet->ip_ttl < 1) {
        printf("Packet timed out. TTL < 1.\n");
        send_icmp_echo_reply(11, 0, packet, sr_get_interface(sr, interface), len, sr);
        return;
    }

    printf("Made it here in the IP section...\n");

    /* Check if the destination IP matches one of the router's interfaces */
    struct sr_if* destination_interface = get_interface_from_ip(sr, ip_packet->ip_dst);

    if (destination_interface || (ip_packet->ip_dst == ~(0x0))) { /* Packet is destined for within network */
        if (ip_packet->ip_p == ip_protocol_icmp) {
            send_icmp_echo_reply(0, 0, packet, sr_get_interface(sr, interface), len, sr);
        } 
        else {
            uint8_t protocol = ip_packet->ip_p;
            if (protocol == ip_protocol_udp) { /* If this is a UDP packet */
                sr_udp_hdr_t* udp_packet = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* Check if this is a RIP packet */
                if (udp_packet->port_dst == htons(520) && udp_packet->port_src == htons(520)) {
                    printf("RIP packet gotten.\n");
                    print_hdrs(packet, len);
                    handle_rip_packet(sr, ip_packet, udp_packet, interface, packet);
                } 
                else {
                    printf("Not RIP packet\n");
                    send_icmp_echo_reply(3, 3, packet, sr_get_interface(sr, interface), len, sr);
                }
            } 
            else { /* TCP packet, we don't deal with this */
                printf("TCP.\n");
                send_icmp_echo_reply(3, 3, packet, sr_get_interface(sr, interface), len, sr);
            }
        }
    } 
    else { /* Packet isn't within network */
        forward_packet(sr, packet, len, ip_packet, interface);
    }
}


int forward_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, sr_ip_hdr_t* ip_header, char* interface) {
    /* If TTL now zero, send time exceeded ICMP error */
    if (ip_header->ip_ttl <= 1) {
      printf("TTL for IP Packet is Zero: Sending ICMP Time Exceeded.\n");
      send_icmp_echo_reply(11, 0, packet, sr_get_interface(sr, interface), len, sr);
      return 1;
    }

    ip_header->ip_ttl--;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl * 4);

    /* Get the router entry from this router's routing table with the longest prefix match to this ip header */
    struct in_addr ip_check;
    ip_check.s_addr = ip_header->ip_dst;
    struct sr_rt* entry = prefix_match(ip_check, sr);

    if (entry == 0 || (entry->metric == htons(INFINITY))) {
        printf("Next hop not found.\n");
        send_icmp_echo_reply(3, 0, packet, sr_get_interface(sr, interface), 0, sr);
        return 1; 
    }

    /* If gateway is 0, next hop IP is destination IP */
    uint32_t next_hop_ip = (entry->gw.s_addr != 0) ? entry->gw.s_addr : ip_header->ip_dst;
    struct sr_arpentry *cache_entry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);

    /* Get the outgoing interface from the routing table entry */
    struct sr_if *out_interface = sr_get_interface(sr, entry->interface);
    if (!out_interface) {
        fprintf(stderr, "Error: Outgoing interface %s not found.\n", entry->interface);
        return 1;
    }
    
    if (cache_entry) {
        /* Update Ethernet header with the correct MAC addresses */
        printf("Entered cache entry\n");
        sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*)packet;
        memcpy(eth_header->ether_dhost, cache_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_header->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, out_interface->name); 
        free(cache_entry);
        return 0;
    }
    else {
        /* Queue ARP request and associate with the outgoing interface */
        printf("Add ARP Request to the queue:\n");
        sr_arpcache_queuereq(&(sr->cache), next_hop_ip, packet, len, out_interface->name);
        return 0; 
    }
}

void handle_rip_packet(struct sr_instance* sr, sr_ip_hdr_t* ip_header, sr_udp_hdr_t* udp_header, char* interface, uint8_t* packet) {
    sr_rip_pkt_t* rip_packet = (sr_rip_pkt_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));

    /* print incoming hdrs */
    printf("Received RIP packet on interface %s:\n", interface);
    uint8_t* packet_start = (uint8_t*)ip_header - sizeof(sr_ethernet_hdr_t);
    uint32_t packet_length = ntohs(ip_header->ip_len) + sizeof(sr_ethernet_hdr_t);
    printf("Printing headers in handle rip before sending\n");
    print_hdrs(packet_start, packet_length);

    switch (rip_packet->command) {
        case 1:  /* RIP Request */
            printf("RIP Request received on interface %s\n", interface);
            send_rip_update(sr);  /* Send RIP response */
            break;
        case 2:  /* RIP Response */
            printf("RIP Response received on interface %s\n", interface);
            update_route_table(sr, ip_header, rip_packet, interface);
            break;
        default:
            fprintf(stderr, "Unknown RIP command received: %d\n", rip_packet->command);
            break;
    }
}

void handle_arp_packet(struct sr_instance* sr, uint8_t* buffer, const char* interface, unsigned int packet_len) {
    /* Extract ARP header from the buffer */
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) buffer;
    uint16_t arp_op = ntohs(arp_hdr->ar_op);

    /* Determine ARP operation (request or reply) */
    if (arp_op == arp_op_request) {
        printf("Handling ARP request");
        /* Allocate memory for ARP reply */
        uint8_t* reply_packet = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) reply_packet;
        sr_arp_hdr_t* reply_hdr = (sr_arp_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));

        /* Populate ARP reply header */
        struct sr_if* iface = sr_get_interface(sr, interface);
        reply_hdr->ar_hrd = htons(arp_hrd_ethernet);
        reply_hdr->ar_pro = htons(ethertype_ip);
        reply_hdr->ar_hln = ETHER_ADDR_LEN;
        reply_hdr->ar_pln = sizeof(uint32_t);
        reply_hdr->ar_op = htons(arp_op_reply);
        reply_hdr->ar_sip = iface->ip;
        reply_hdr->ar_tip = arp_hdr->ar_sip;
        memcpy(reply_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
        memcpy(reply_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);

        /* Populate Ethernet header */
        memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ethertype_arp);

        /* Send the ARP reply */
        printf("Sending ARP reply.\n");
        sr_send_packet(sr, reply_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface->name);
        free(reply_packet);

    } else if (arp_op == arp_op_reply) {
        printf("Handling ARP reply\n");

        /* Update ARP cache with the received reply */
        struct sr_arpreq* arp_request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

        if (arp_request) {
            printf("Processing queued packets for IP: %s\n", inet_ntoa(*(struct in_addr*)&arp_request->ip));
            struct sr_packet* queued_packet = arp_request->packets;

            while (queued_packet) {
                sr_ethernet_hdr_t* queued_eth_hdr = (sr_ethernet_hdr_t*) queued_packet->buf;

                /* Update Ethernet header with ARP reply info */
                memcpy(queued_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                struct sr_if* iface = sr_get_interface(sr, queued_packet->iface);
                memcpy(queued_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

                printf("Forwarding queued packet.\n");
                if (sr_send_packet(sr, queued_packet->buf, queued_packet->len, queued_packet->iface) != 0) {
                    fprintf(stderr, "Error: Failed to forward queued packet.\n");
                } 
                else {
                    printf("Queued packet forwarded successfully.\n");
                }

                queued_packet = queued_packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), arp_request);
        } 
        else {
            printf("No pending requests found\n");
        }
    } 
    else {
        printf("Unknown type"); /* ARP code not request or reply */
    }
}

struct sr_if* get_interface_from_ip(struct sr_instance* sr, uint32_t ip) {
	struct sr_if* interface_match = sr->if_list;
	while(interface_match) {
		if (interface_match->ip == ip) {
			return interface_match;
		}
		interface_match = interface_match->next;
	}
	return 0;
}


struct sr_rt* prefix_match(struct in_addr addr, struct sr_instance* sr){
  struct sr_rt *longest_match = NULL;
  int longest = -1;
  struct sr_rt* cur_entry = sr->routing_table;
  while (cur_entry != 0) { 
    if ((addr.s_addr & cur_entry->mask.s_addr) == (cur_entry->dest.s_addr & cur_entry->mask.s_addr)) { 
      if(!longest_match || cur_entry->mask.s_addr >= longest) {
        longest = cur_entry->mask.s_addr;
        longest_match = cur_entry;
      }
    }
    cur_entry = cur_entry->next;
  }
  return longest_match;
}

int send_icmp_echo_reply(uint8_t type, uint8_t code, uint8_t* packet, struct sr_if* interface, unsigned int len, struct sr_instance* sr) {
	
        sr_ip_hdr_t* incoming_ip_hdr = (sr_ip_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
        unsigned int icmp_len = 0;
        unsigned int total_size = 0;

        switch (type) {
            case 11:
                icmp_len = sizeof(sr_icmp_t3_hdr_t) + htons(incoming_ip_hdr->ip_len);
                total_size = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+icmp_len;
                break;
            case 3:
                icmp_len = sizeof(sr_icmp_t3_hdr_t)+ htons(incoming_ip_hdr->ip_len);
                total_size = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+icmp_len;
                break;
            default: {
                    struct sr_if* ip_check_iface = get_interface_from_ip(sr, incoming_ip_hdr->ip_dst);
                    if (sr_obtain_interface_status(sr, ip_check_iface->name)==0) {
                        printf("Interface is not up, ICMP exception is now sent.\n");
                        send_icmp_echo_reply(3, 0, packet, interface, len, sr);
                        return 0;
                    }
                    icmp_len = sizeof(sr_icmp_hdr_t);
                    total_size = len;
                    break;
                }
            }
        
        uint8_t* client_memory = (uint8_t*) malloc(total_size);
        populate_icmp_header_switch(type, code, incoming_ip_hdr, client_memory, icmp_len, packet, len);
        
        sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)client_memory;
        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(client_memory+sizeof(sr_ethernet_hdr_t));

        struct in_addr ip_check;
        ip_check.s_addr = incoming_ip_hdr->ip_src;
        struct sr_rt* routing_table_entry = prefix_match(ip_check, sr);
        struct sr_if* iface = sr_get_interface(sr, routing_table_entry->interface);
        populate_ip_header(type, incoming_ip_hdr, ip_header, icmp_len);
        

        ethernet_header->ether_type = htons(ethertype_ip);
        uint32_t nh_addr = 0;
        if (routing_table_entry->gw.s_addr == 0) {
            nh_addr = incoming_ip_hdr->ip_src;
        } 
        else {
            nh_addr = routing_table_entry->gw.s_addr;
        }
        struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, nh_addr);
        struct sr_if* iface2 = sr_get_interface(sr, iface->name);
        
        if (entry) {
            printf("Forwarding packet to MAC address.\n");
            memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
            memcpy(ethernet_header->ether_shost, iface2->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, client_memory, total_size, iface->name);
        } 
        else {
            printf("No MAC entry found, added to queue\n");
            print_hdrs(client_memory, total_size);
            sr_arpcache_queuereq(&(sr->cache), nh_addr, client_memory, total_size, iface2->name);
        }
        return 0;
}

/* ICMP Helpers */
void populate_icmp_header_switch(uint8_t type, uint8_t code, sr_ip_hdr_t* incoming_ip_hdr, uint8_t* client_memory, unsigned int icmp_len, uint8_t* packet, unsigned int len) {
    switch (type) {
        case 3:
        case 11: {
            sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t*) (client_memory + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_t3_hdr->icmp_type = type;
            icmp_t3_hdr->next_mtu = 0;
            icmp_t3_hdr->unused = 0;

            int i;
            for (i = 0; i < ICMP_DATA_SIZE; i++) icmp_t3_hdr->data[i] = *((uint8_t*) incoming_ip_hdr + i);
            icmp_t3_hdr->icmp_code = (type == 0) ? 0 : code;		
            icmp_t3_hdr->icmp_sum = 0;
            icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, icmp_len);
            break;
        }
        default: { 
            int k;
            for (k = 0; k < len; k++) client_memory[k] = packet[k];
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) (client_memory + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = 0;
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            break;
        }
    }
}

void populate_ip_header(uint8_t type, sr_ip_hdr_t* incoming_ip_hdr, sr_ip_hdr_t* ip_header, unsigned int icmp_len) {
    if (type != 0) {
        ip_header->ip_id = htons(incoming_ip_hdr->ip_id) + 1;
        ip_header->ip_off = htons(IP_DF);
        ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_len);
        ip_header->ip_src = incoming_ip_hdr->ip_dst;
        ip_header->ip_dst = incoming_ip_hdr->ip_src;
        ip_header->ip_v = 4;
        ip_header->ip_tos = 0;
        ip_header->ip_ttl = 64;
        ip_header->ip_p = ip_protocol_icmp;
        ip_header->ip_hl = 5;
    } 
    else {
        ip_header->ip_p = ip_protocol_icmp;
        ip_header->ip_src = incoming_ip_hdr->ip_dst;
        ip_header->ip_dst = incoming_ip_hdr->ip_src;
        ip_header->ip_ttl = 64;
        ip_header->ip_tos = 0;
    }

    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
}
