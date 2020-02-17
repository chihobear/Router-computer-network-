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

#include "sr_protocol.h"
#include "pwospf_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;
struct unhandled;
struct pwospf_subsys;
struct seq_rt;
struct database;
struct database_list;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct unhandled{
    uint8_t* packet;
    unsigned long size;
    struct unhandled* next;
};

struct seq_rt{
    uint32_t RID;
    uint16_t sequence;
    struct seq_rt* next;
};

struct database_list{
    uint32_t RID;
    uint32_t subnet;
    uint32_t mask;
    struct database_list* next;
};

struct database{
    uint32_t RID;
    time_t time;
    struct database_list* right;
    struct database* next;
};

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct unhandled* un_packet;
    uint16_t sequence;
    struct seq_rt* s_rt;
    struct database* db;
    
    FILE* logfile;
    volatile uint8_t  hw_init; /* bool : hardware has been initialized */

    /* -- pwospf subsystem -- */
    struct pwospf_subsys* ospf_subsys;
    uint32_t RID;
    uint32_t AID;
    uint16_t lsuint;
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

void sr_arprequest(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int length);
void processIP(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int length);
void IPForwarding(struct sr_instance* sr, uint8_t* packet, unsigned char* macd, unsigned char* macs, char* interface, unsigned int length);
void sendARP(struct sr_instance* sr, char* interface, uint32_t gw, struct ip* ips);
void sr_arpreply(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int length);
void arp_cache_update(struct sr_instance* sr, char* interface, uint8_t* mac, uint32_t ips);
void sendICMP(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int length);
uint16_t calculate_checksum(uint8_t* start, unsigned long length);
void add_unhandled(struct sr_instance* sr, uint8_t* packet, unsigned long size);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

void LSU_process(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr, uint32_t source, uint8_t *packet, int len, char* interface);
void database_update(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr);
void router_table_update(struct sr_instance* sr);
struct in_addr construct_in_addr(uint32_t value);
struct sr_if* update_table_find_interface(struct sr_instance* sr, uint32_t subnet, uint32_t mask);
struct sr_if* table_find_interface_RID(struct sr_instance* sr, uint32_t RID);
struct database* find_database_entry(struct database* db,  uint32_t RID);
int judge_visited(uint32_t RID_arr[], uint32_t RID, struct sr_instance* sr);
void add_default_path(struct sr_instance* sr, struct sr_rt** rt);
void forward_ospf(struct sr_instance* sr, uint8_t *packet, int len, char* interface);
int if_link_change(struct database* db, struct database_list* dbl, uint32_t* data, int size);
void clear_router_table(struct sr_instance* sr);
int host_type(struct sr_instance *sr, struct database_list *dbl);

#endif /* SR_ROUTER_H */
