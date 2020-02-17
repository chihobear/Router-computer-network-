/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"
#include "pwospf_protocol.h"
#include "sr_if.h"
#include "sr_rt.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>


/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);
static void* pwospf_run_thread_LSU(void* arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    //If the router is loaded a full routing table, enable OSPF protocol
    if(sr->routing_table != NULL && (sr->routing_table)->next != NULL) return 0;
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);
    pthread_mutex_init(&(sr->ospf_subsys->lock_LSU), 0);


    /* -- handle subsystem initialization here! -- */

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        assert(0);
    }
    
    if( pthread_create(&sr->ospf_subsys->thread_LSU, 0, pwospf_run_thread_LSU, sr)) {
        perror("pthread_LSU_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_lock_LSU
 *
 * Lock mutex associated with pwospf_LSU
 *
 *---------------------------------------------------------------------*/

void pwospf_lock_LSU(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock_LSU) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock_LSU
 *
 * Unlock mutex associated with pwospf LSU
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock_LSU(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock_LSU) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        pwospf_lock(sr->ospf_subsys);
        
        //send hello message
        send_hello(sr);
        sleep(OSPF_DEFAULT_HELLOINT);
        
        pwospf_unlock(sr->ospf_subsys);
    };
    return NULL;
} /* -- run_ospf_thread -- */

static void* pwospf_run_thread_LSU(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        pwospf_lock_LSU(sr->ospf_subsys);
        (sr->lsuint)--;
        sleep(1);
        //send hello message
        if(sr->lsuint <= 0){
            send_LSU(sr);
            sr->lsuint = (uint16_t)OSPF_DEFAULT_LSUINT;
        }
        
        pwospf_unlock_LSU(sr->ospf_subsys);
    };
    return NULL;
} /* -- run_ospf_thread -- */

uint16_t ospf_checksum(uint8_t* start, unsigned long length){
    uint16_t* temp;
    uint32_t check = 0;
    int i = 0, byte_num = length * 2;
    for(i = 0;i < byte_num;i++){
        if(i <= 11 && i >= 8) check += ntohs(*(uint16_t*)(start+i*2));
    }
    check = (check & 0xffff) + (check >> 16);
    temp = (uint16_t*)(&check);
    *temp = htons(*temp);
    *temp = (*temp) ^ 0xffff;
    return *temp;
}

void clear_hello_result(struct sr_instance *sr){
    struct sr_if *ifs = sr->if_list;
    while(ifs != NULL){
        if(ifs->neighbors != NULL && (time(NULL) - ifs->neighbors->update_time) >= OSPF_NEIGHBOR_TIMEOUT){
            free(ifs->neighbors);
            ifs->neighbors = NULL;
        }
        ifs = ifs->next;
    }
}

void send_hello(struct sr_instance *sr){
    struct sr_if *ifs = sr->if_list;
    uint8_t *packet = NULL;
    struct sr_ethernet_hdr* ethernet_hdr = NULL;
    struct ip* ip_hdr = NULL;
    struct ospfv2_hdr* ospf_hdr = NULL;
    struct ospfv2_hello_hdr* hello_hdr = NULL;
    struct in_addr* temp;
    int len = 0, i = 0;
    
    clear_hello_result(sr);
    
    while(ifs != NULL){
        len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
        sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);
        packet = (uint8_t*)malloc(len);
        
        //ethernet
        ethernet_hdr = (struct sr_ethernet_hdr*)packet;
        for(i = 0;i < ETHER_ADDR_LEN;i++) ethernet_hdr->ether_dhost[i] = 0xff;
        memcpy(ethernet_hdr->ether_shost, ifs->addr, ETHER_ADDR_LEN);
        ethernet_hdr->ether_type = htons(ETHERTYPE_IP);
        
        //IP hdr
        ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = sizeof(struct ip) / 4;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 255;
        ip_hdr->ip_p = 0x89;       //ospf
        temp = (struct in_addr*)malloc(sizeof(struct in_addr));
        temp->s_addr = ifs->ip;
        ip_hdr->ip_src = *temp;
        temp = (struct in_addr*)malloc(sizeof(struct in_addr));
        temp->s_addr = htonl(OSPF_AllSPFRouters);
        ip_hdr->ip_dst = *temp;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = calculate_checksum((uint8_t*)ip_hdr, ip_hdr->ip_hl);
        
        //ispfv2_hdr
        ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
        ospf_hdr->version = OSPF_V2;
        ospf_hdr->type = OSPF_TYPE_HELLO;
        ospf_hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
        ospf_hdr->rid = sr->RID;
        ospf_hdr->aid = sr->AID;
        ospf_hdr->autype = 0;
        ospf_hdr->audata = 0;
        
        //hello_hdr
        hello_hdr = (struct ospfv2_hello_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
        hello_hdr->nmask = ifs->mask;
        hello_hdr->helloint = htons(ifs->helloint);
        hello_hdr->padding = 0;
        ospf_hdr->csum = ospf_checksum((uint8_t*)ospf_hdr, htons(ospf_hdr->len) / 4);
        sr_send_packet(sr, packet, len, ifs->name);
        ifs = ifs->next;
    }
}

void send_LSU(struct sr_instance* sr){
    struct sr_if *ifs = sr->if_list, *if_temp = sr->if_list;
    uint8_t *packet = NULL;
    struct sr_ethernet_hdr* ethernet_hdr = NULL;
    struct ip* ip_hdr = NULL;
    struct ospfv2_hdr* ospf_hdr = NULL;
    struct ospfv2_lsu_hdr* lsu_hdr = NULL;
    struct in_addr* temp;
    int len = 0, i = 0;
    uint32_t interface_num = 0;
    uint32_t *temp_space  = NULL;
    while(if_temp != NULL){
        if_temp = if_temp->next;
        interface_num++;
    }
    len = interface_num;
    temp_space = (uint32_t*)malloc(len*3*sizeof(uint32_t));
    if_temp = sr->if_list;
    while(if_temp != NULL){
        memcpy(temp_space + i * 3, &(if_temp->ip), 4);
        memcpy(temp_space + i * 3 + 1, &(if_temp->mask), 4);
        if(if_temp->neighbors == NULL){
            const uint32_t rid = 0;
            memcpy(temp_space + i * 3 + 2, &rid, 4);
        }
        else memcpy(temp_space + i * 3 + 2, &(if_temp->neighbors->neighbor_RID), 4);
        i++;
        if_temp = if_temp->next;
    }
    
    (sr->sequence)++;
    while(ifs != NULL){
        len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
        sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + interface_num*12;
        packet = (uint8_t*)malloc(len);
        
        //ethernet
        ethernet_hdr = (struct sr_ethernet_hdr*)packet;
        for(i = 0;i < ETHER_ADDR_LEN;i++) ethernet_hdr->ether_dhost[i] = 0xff;
        memcpy(ethernet_hdr->ether_shost, ifs->addr, ETHER_ADDR_LEN);
        ethernet_hdr->ether_type = htons(ETHERTYPE_IP);
        
        //IP hdr
        ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = sizeof(struct ip) / 4;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 255;
        ip_hdr->ip_p = 0x89;       //ospf
        temp = (struct in_addr*)malloc(sizeof(struct in_addr));
        temp->s_addr = ifs->ip;
        ip_hdr->ip_src = *temp;
        temp = (struct in_addr*)malloc(sizeof(struct in_addr));
        temp->s_addr = htonl(OSPF_AllSPFRouters);
        ip_hdr->ip_dst = *temp;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = calculate_checksum((uint8_t*)ip_hdr, ip_hdr->ip_hl);
        
        //ispfv2_hdr
        ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
        ospf_hdr->version = OSPF_V2;
        ospf_hdr->type = OSPF_TYPE_LSU;
        ospf_hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + interface_num * 12);
        ospf_hdr->rid = sr->RID;
        ospf_hdr->aid = sr->AID;
        ospf_hdr->autype = 0;
        ospf_hdr->audata = 0;
        
        //lsu_hdr
        lsu_hdr = (struct ospfv2_lsu_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
        lsu_hdr->seq = htons(sr->sequence);
        lsu_hdr->unused = 0;
        lsu_hdr->ttl = 255;
        lsu_hdr->num_adv = htonl(interface_num);
        memcpy(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr), temp_space, interface_num*12);
        ospf_hdr->csum = ospf_checksum((uint8_t*)ospf_hdr, htons(ospf_hdr->len) / 4);
        
        //printf("Database Updated!!!!!!\n");
        sr_send_packet(sr, packet, len, ifs->name);
        ifs = ifs->next;
    }
    //After send the packet, update the self-entry in the database
    database_update(sr, ospf_hdr);
}

