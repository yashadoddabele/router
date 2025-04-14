/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_lock));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_lock));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%d\t",entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */

/* Function to remove a routing table entry */
void sr_remove_rt_entry(struct sr_instance* sr, struct sr_rt* entry) {
    if (!sr->routing_table || !entry) return;

    if (sr->routing_table == entry) {
        sr->routing_table = entry->next;
        free(entry);
        return;
    }

    struct sr_rt *prev = sr->routing_table;
    struct sr_rt *curr = sr->routing_table->next;
    while (curr) {
        if (curr == entry) {
            prev->next = curr->next;
            free(curr);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

/*-----------------------------------------------------------------------------
 * Function: sr_rip_timeout
 * Scope:    Global
 *
 * This function periodically checks the routing table for expired routes and
 * sends periodic RIP updates every 5 seconds.
 *
 *---------------------------------------------------------------------------*/

void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
	
    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_lock));
		time_t current_time;
		time(&current_time);
        poison_routes_for_inactive_interfaces(sr);
   
        struct sr_rt *rt_entry = sr->routing_table;
        while (rt_entry && rt_entry->next) {
            struct sr_rt *next_entry = rt_entry->next;
            if (next_entry->updated_time - current_time <= 20) {
                rt_entry = next_entry; /* Move to the next entry */
            } 
            else {
                rt_entry->next = next_entry->next; /* Remove expired entry */
            }
        }

		send_rip_update(sr);
        pthread_mutex_unlock(&(sr->rt_lock));
    }
}


/*-----------------------------------------------------------------------------
 * Function: send_rip_request
 * Scope:    Global
 *
 * Sends a RIP request packet out of all interfaces.
 *
 *---------------------------------------------------------------------------*/

void send_rip_request(struct sr_instance *sr) {
    size_t packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
    uint8_t* packet = (uint8_t*) malloc(packet_len);

    if (!packet) {
        fprintf(stderr, "Failed to allocate memory for RIP request packet.\n");
        return;
    }

    memset(packet, 0, packet_len);

    /* RIP header */
    sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
    rip_hdr->command = 1; /* RIP Request */
    rip_hdr->version = 2; /* RIP v2 */

    /* UDP header */
    sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    udp_hdr->port_src = htons(520);
    udp_hdr->port_dst = htons(520);
    udp_hdr->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
    udp_hdr->udp_sum = 0;
    udp_hdr->udp_sum = cksum(udp_hdr, udp_hdr->udp_len);

    /* IP header */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = ip_protocol_udp;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
    ip_hdr->ip_dst = ~(0x0); /* Broadcast address */

    /* Ethernet header */
    sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packet;
    ether_hdr->ether_type = htons(ethertype_ip);
    memset(ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);


    /* Send out of each interface */
    struct sr_if* if_list = sr->if_list;
    while (if_list) {
        send_rip_request_on_interface(sr, packet, if_list);
        if_list = if_list->next;
    }
    free(packet);
}


/*-----------------------------------------------------------------------------
 * Function: send_rip_update
 * Scope:    Global
 *
 * Sends RIP response packets (updates) out of all interfaces.
 * Implements Split Horizon with Poison Reverse.
 *
 *---------------------------------------------------------------------------*/

void send_rip_update(struct sr_instance *sr) {
    pthread_mutex_lock(&(sr->rt_lock));

    /* For each interface, send RIP update (RIP Response) */
    struct sr_if *iface = sr->if_list;
    while (iface) {
        /* Prepare the RIP response */
        struct sr_rip_pkt rip_response;
        memset(&rip_response, 0, sizeof(rip_response));
        rip_response.command = 2; /* RIP Response */
        rip_response.version = 2; /* RIP v2 */

        int entries = 0;
        struct sr_rt *rt_entry = sr->routing_table;

        /* Copy each routing table entry into the RIP packet entries */
        while (rt_entry && entries < MAX_NUM_ENTRIES) {
            rip_response.entries[entries].afi = htons(2); /* IP */
            rip_response.entries[entries].tag = 0;
            rip_response.entries[entries].address = rt_entry->dest.s_addr;
            rip_response.entries[entries].mask = rt_entry->mask.s_addr;
            rip_response.entries[entries].next_hop = 0;

            /* If route learned from the same interface, poison it */
            if (strcmp(rt_entry->interface, iface->name) == 0) {
                rip_response.entries[entries].metric = htonl(INFINITY);
            } else {
                rip_response.entries[entries].metric = rt_entry->metric;
            }
            entries++;
            rt_entry = rt_entry->next;
        }

        /* Fill remaining entries with "empty" routes (INFINITY metrics) if any */
        while (entries < MAX_NUM_ENTRIES) {
            rip_response.entries[entries].afi = htons(2);
            rip_response.entries[entries].tag = 0;
            rip_response.entries[entries].address = 0;
            rip_response.entries[entries].mask = 0;
            rip_response.entries[entries].next_hop = 0;
            rip_response.entries[entries].metric = htonl(INFINITY);
            entries++;
        }

        /* The RIP packet is fixed-size in this approach: sr_rip_pkt_t includes MAX_NUM_ENTRIES */
        size_t rip_packet_size = sizeof(sr_rip_pkt_t);

        /* Prepare Ethernet header */
        sr_ethernet_hdr_t eth_hdr;
        memcpy(eth_hdr.ether_shost, iface->addr, ETHER_ADDR_LEN); 
        memset(eth_hdr.ether_dhost, 0xFF, ETHER_ADDR_LEN); 
        eth_hdr.ether_type = htons(ethertype_ip);

        /* Prepare IP header */
        sr_ip_hdr_t ip_hdr;
        ip_hdr.ip_hl = 5;
        ip_hdr.ip_v = 4;
        ip_hdr.ip_tos = 0; 
        ip_hdr.ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + rip_packet_size);
        ip_hdr.ip_id = htons(0);
        ip_hdr.ip_off = htons(IP_DF);
        ip_hdr.ip_ttl = 64; 
        ip_hdr.ip_p = ip_protocol_udp; 
        ip_hdr.ip_src = iface->ip;
        /* Use broadcast destination like their code */
        ip_hdr.ip_dst = ~(0x0);
        ip_hdr.ip_sum = 0;
        ip_hdr.ip_sum = cksum(&ip_hdr, sizeof(sr_ip_hdr_t));  

        /* Prepare UDP header */
        sr_udp_hdr_t udp_hdr;
        udp_hdr.port_src = htons(520);
        udp_hdr.port_dst = htons(520);  
        udp_hdr.udp_len = htons(sizeof(sr_udp_hdr_t) + rip_packet_size);
        udp_hdr.udp_sum = 0;
        /* Compute UDP checksum similar to their code */
        udp_hdr.udp_sum = cksum(&udp_hdr, ntohs(udp_hdr.udp_len));

        /* Combine headers and RIP payload into a packet */
        size_t packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + rip_packet_size;
        uint8_t *packet = malloc(packet_len);
        if (!packet) {
            printf("Could not allocate memory for RIP update packet\n");
            pthread_mutex_unlock(&(sr->rt_lock));
            return;
        }

        /* Copy headers and RIP packet into the final packet */
        memcpy(packet, &eth_hdr, sizeof(sr_ethernet_hdr_t));
        memcpy(packet + sizeof(sr_ethernet_hdr_t), &ip_hdr, sizeof(sr_ip_hdr_t));
        memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &udp_hdr, sizeof(sr_udp_hdr_t));
        memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t), &rip_response, rip_packet_size);

        /* Send the packet */
        if (sr_send_packet(sr, packet, packet_len, iface->name) < 0) {
            fprintf(stderr, "Failed to send RIP update on interface %s\n", iface->name);
        } else {
            printf("RIP response sent on interface %s\n", iface->name);
        }

        free(packet);
        iface = iface->next;
    }

    pthread_mutex_unlock(&(sr->rt_lock));
}

void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet, sr_rip_pkt_t* rip_packet, char* iface) {
    pthread_mutex_lock(&(sr->rt_lock));

    int triggered_update_needed = 0;

    int valid_entry = 0;
    int i;
    struct sr_rt* entry_table = sr->routing_table;

    for (i = 0; i < MAX_NUM_ENTRIES; i++) { /* Loop through all 25 entries to find the valid ones*/
        struct entry *rip_entry = &rip_packet->entries[i];
        valid_entry = 0;
        entry_table = sr->routing_table;

        while (entry_table && (valid_entry == 0)) { /* Compare entry w/ others in routing table */
            if (rip_entry->address == entry_table->dest.s_addr) {
                if (entry_table->gw.s_addr != 0x0) { /* It's not for this interface */
                    entry_table->updated_time = time(NULL);
                    if (entry_table->metric > (rip_entry->metric +1)) { /* Old metric higher, update routing table entry */
                        triggered_update_needed = 1; /* This changes the routing table so we need to send a RIP response */
                        entry_table->metric = rip_entry->metric + 1;
                        entry_table->gw.s_addr = ip_packet->ip_src;
                        strncpy(entry_table->interface, iface, sr_IFACE_NAMELEN);
                    }
                } 
                else { /* Is for this interface */
                    if (sr_obtain_interface_status(sr, entry_table->interface)!=0) {
                        entry_table->metric = 0; /* Set metric to zero since interface is up */
                    }
                }
                valid_entry = 1;
            }
            entry_table = entry_table->next;
        }

        if (!valid_entry) {
            printf("No valid entry found, adding one now\n");
            struct in_addr new_address;
            struct in_addr new_mask;
            struct in_addr new_gw;

            new_address.s_addr = rip_entry->address;
            new_mask.s_addr = rip_entry->mask;
            new_gw.s_addr = ip_packet->ip_src;

            sr_add_rt_entry(sr, new_address, new_gw, new_mask, rip_entry->metric + 1, iface);
            triggered_update_needed = 1; /* Changed routing table, need to send RIP repsonse */
        }
    }

    /* If this was set to 1, that meant we updated the route table at some point*/
    if (triggered_update_needed) {
        send_rip_update(sr); /* Send rip response */
    }
    pthread_mutex_unlock(&(sr->rt_lock));
}

/* Helpers */

void poison_routes_for_inactive_interfaces(struct sr_instance *sr) {
    struct sr_if *iface = sr->if_list;
    while (iface) {
        /* Check if the interface is inactive */
        if (sr_obtain_interface_status(sr, iface->name) == 0) {
            struct sr_rt *rt_entry = sr->routing_table;
            while (rt_entry) {
                /* Poison routes learned via the inactive interface */
                if (strcmp(rt_entry->interface, iface->name) == 0) {
                    rt_entry->metric = htons(INFINITY);
                }
                rt_entry = rt_entry->next;
            }
        }
        iface = iface->next;
    }
}

void send_rip_request_on_interface(struct sr_instance *sr, uint8_t *packet, struct sr_if *iface) {
    sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_src = iface->ip; 
    memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN); /* Set source IP and MAC for this interface */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t)); /* Recalculate IP checksum now that ip_src is set */
    size_t packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
    print_hdrs(packet, packet_len);
    int success = sr_send_packet(sr, packet, (unsigned int)packet_len, iface->name);
}