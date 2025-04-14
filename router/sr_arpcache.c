#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/* 
  This function is designed to periodically check the list of pending ARP requests and 
  decide whether each request should be retransmitted or discarded. 
  This function iterates over the ARP request queue and calls handle_arpreq for each 
  pending request. 
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    struct sr_arpreq *curr_req = (&(sr->cache))->requests; /* Gets the pending list of requests */
    struct sr_arpreq *next_req;
    while (curr_req) {
        next_req = curr_req->next; 
        handle_arpreq(sr, curr_req);
        curr_req = next_req;
    }
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t now = time(NULL);
    if (difftime(now, req->sent) >= 1.0) {
        if (req->times_sent >= 5) { /* If ARP request is sent 5 times without reply, we send an ICMP error */
            struct sr_packet *queued_packet = req->packets;
            while (queued_packet) {
                /* Send ICMP error packet back to the orig interface */
                printf("Sending ICMP error to %s\n", queued_packet->iface);
                send_icmp_error(3, 1, sr, queued_packet->buf, queued_packet->len, queued_packet->iface);
                queued_packet = queued_packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), req);
            return;
        }
        else {
            printf("We are sending an arp req back\n");
            send_arp_request(sr, req, req->ip, req->packets->iface);
            req->sent = now;
            req->times_sent++;
            return;
        }
    }
}

/* 
    The send_icmp_error function constructs this ICMP message, encapsulates it in an IP 
    and Ethernet frame, and sends it back to the sender of the undeliverable packet. 
*/
void send_icmp_error(u_int8_t type, u_int8_t code, struct sr_instance *sr, uint8_t *undelivered_buffer, unsigned int len, char *iface) { 
    struct sr_if *interface = sr_get_interface(sr, iface);
    
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) || !interface) {
        fprintf(stderr, "Error in send_icmp_error");
        return;
    }

    /* Get old ethernet/IP headers from the undelivered packet */
    struct sr_ethernet_hdr *old_ether_header = (struct sr_ethernet_hdr *)undelivered_buffer;
    struct sr_ip_hdr *old_ip_header = (struct sr_ip_hdr *)(undelivered_buffer + sizeof(struct sr_ethernet_hdr));

    /* Allocate memory for ICMP packet */
    unsigned int icmp_packet_size = sizeof(sr_icmp_t3_hdr_t);
    unsigned int ip_packet_size = sizeof(sr_ip_hdr_t) + icmp_packet_size;
    unsigned int ether_frame_size = sizeof(sr_ethernet_hdr_t) + ip_packet_size;
    uint8_t *packet = (uint8_t*)malloc(ether_frame_size);
    
    /* Create new ethernet header */
    sr_ethernet_hdr_t *ether_header = (sr_ethernet_hdr_t *) packet;
    memcpy(ether_header->ether_dhost, old_ether_header->ether_shost, ETHER_ADDR_LEN); 
    memcpy(ether_header->ether_shost, interface->addr, ETHER_ADDR_LEN); 
    ether_header->ether_type = htons(ethertype_ip);
    
    /* Create new IPv4 header */
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    new_ip_hdr->ip_v = 4;
    new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    new_ip_hdr->ip_tos = 0;
    new_ip_hdr->ip_len = htons(ip_packet_size);
    new_ip_hdr->ip_id = htons(0); 
    new_ip_hdr->ip_off = htons(IP_DF); 
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_p = ip_protocol_icmp;
    new_ip_hdr->ip_src = interface->ip;
    new_ip_hdr->ip_dst = old_ip_header->ip_src;
    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

    /* Create ICMP Header */
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;                            
    icmp_hdr->icmp_code = code;                       
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;

    /* 
    Copy header, first 8 bytes of original payload to ICMP data field, compute the 
    checksum, send the packet, then free the memory.
    */
    unsigned int icmp_data_size = ICMP_DATA_SIZE;
    unsigned int length_to_copy = sizeof(sr_ip_hdr_t) + 8;
    if (len - sizeof(sr_ethernet_hdr_t) < length_to_copy) {
        length_to_copy = len - sizeof(sr_ethernet_hdr_t);
    }
    if (length_to_copy > icmp_data_size) {
        length_to_copy = icmp_data_size;
    }
    memcpy(icmp_hdr->data, old_ip_header, length_to_copy);
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
    sr_send_packet(sr, packet, ether_frame_size, iface);
    free(packet);
}

/*
    The router calls send_arp_request when it needs to send a packet to a destination IP 
    address but doesn’t yet know the corresponding MAC address. 
    
    By broadcasting an ARP request on the network, the router asks everyone for info about
    the MAC address. Devices on the local network with that IP address will respond with 
    an ARP reply containing their MAC address.
 */
void send_arp_request(struct sr_instance *sr, struct sr_arpreq *req, uint32_t ip, const char *iface) {
    struct sr_if *interface = sr_get_interface(sr, iface);
    struct sr_ethernet_hdr *eth_hdr;
    struct sr_arp_hdr *arp_hdr;
    uint8_t *packet;
    
    /* Allocate memory for the Ethernet frame + ARP packet */ 
    packet = (uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr));
    if (!packet) {
        fprintf(stderr, "Failed to allocate memory for ARP request\n");
        return;
    }

    /* Set Ethernet header */
    eth_hdr = (struct sr_ethernet_hdr *)packet;
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN); 
    memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN); /* broadcast (FF:FF:FF:FF:FF:FF) */
    eth_hdr->ether_type = htons(ethertype_arp); 

    /* Set ARP header */ 
    arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet); 
    arp_hdr->ar_pro = htons(ethertype_ip); 
    arp_hdr->ar_hln = ETHER_ADDR_LEN; 
    arp_hdr->ar_pln = sizeof(uint32_t); 
    arp_hdr->ar_op = htons(arp_op_request); 

    /* Set the source MAC and IP address */ 
    memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN); /* Source MAC address */
    arp_hdr->ar_sip = interface->ip; /* Source IP address (this is the interface's IP) */

    /* Set the target MAC and IP address */
    memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN); /* Target MAC address (unknown) */
    arp_hdr->ar_tip = ip; /* Target IP address (the IP we're querying) */
    
    printf("Almost ready to send arp request packet\n");
    sr_send_packet(sr, packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), iface);
    free(packet);
}


/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
    
    pthread_mutex_unlock(&(cache->lock));
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

