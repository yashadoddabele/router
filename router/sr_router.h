/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <pthread.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* Debugging Macros */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

/* Constants */
#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* Forward Declarations */
struct sr_if;
struct sr_rt;
struct sr_arpreq;
struct sr_packet;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_if_status_cache * if_cache; /* interfaces' status cache */
    pthread_mutex_t rt_lock; 
    pthread_mutexattr_t rt_lock_attr;
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    pthread_attr_t rt_attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

/* -- helpers */
int send_icmp_echo_reply(uint8_t type, uint8_t code, uint8_t* packet, struct sr_if* interface, unsigned int len, struct sr_instance* sr);
int forward_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, sr_ip_hdr_t* ip_header, char* interface);
struct sr_rt* prefix_match(struct in_addr addr, struct sr_instance* sr);
struct sr_if* get_interface_from_ip(struct sr_instance* sr, uint32_t ip);
int forward_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, sr_ip_hdr_t* ip_header, char* interface);
void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void handle_rip_packet(struct sr_instance* sr, sr_ip_hdr_t* ip_header, sr_udp_hdr_t* udp_header, char* interface, uint8_t* packet);
void handle_arp_packet(struct sr_instance* sr, uint8_t* buffer, const char* interface, unsigned int packet_len);
void populate_icmp_header_switch(uint8_t type, uint8_t code, sr_ip_hdr_t* incoming_ip_hdr, uint8_t* client_memory, unsigned int icmp_len, uint8_t* packet, unsigned int len);
void populate_ip_header(uint8_t type, sr_ip_hdr_t* incoming_ip_hdr, sr_ip_hdr_t* ip_header, unsigned int icmp_len);

#endif /* SR_ROUTER_H */