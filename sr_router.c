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
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"

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

    /* Add initialization code here! */
    sr->un_packet = NULL;
    sr->AID = 0;
    sr->lsuint = (uint16_t)OSPF_DEFAULT_LSUINT;
    sr->sequence = 0;
    sr->s_rt = 0;
    sr->db = 0;
    
   /* moved to sr_vns_comm.c, after HWINFO has been received and processed */
   /* pwospf_init(sr); */
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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    //struct ip* ips;
    struct sr_ethernet_hdr* ethernets;
    struct sr_arphdr* arps;
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

//    int x = 0;
//    printf("------------\n");
//    for(x = 0;x < len;x++){
//        printf("%x ", packet[x]);
//    }
//    printf("============\n");
//    printf("*** -> Received packet of length %d \n",len);
    
    //analysis ethernet packet
    ethernets = (struct sr_ethernet_hdr*)packet;
    //ARP
    if(ethernets->ether_type == htons(ETHERTYPE_ARP)){
        arps = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
        //Request
        if(arps->ar_op == htons(ARP_REQUEST)){
            sr_arprequest(sr, packet, interface, len);
        }
        //Reply
        else if(arps->ar_op == htons(ARP_REPLY)){
            sr_arpreply(sr, packet, interface, len);
        }
    }
    //IP
    else if(ethernets->ether_type == htons(ETHERTYPE_IP)){
        processIP(sr, packet, interface, len);
    }

}/* end sr_ForwardPacket */


/*---------------------------------------------------------------------
 * Method: ARPRequest
 *
 *---------------------------------------------------------------------*/
void sr_arprequest(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int length){
    struct sr_if* ifs;
    ifs = sr->if_list;
    uint8_t* packetN;
    struct sr_ethernet_hdr* ethernets;
    struct sr_arphdr* arps;
    
    //Judge the length of the packet
    if(length != sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr)) return;
    
    while(ifs != NULL){
        if(strcmp(ifs->name, interface) == 0) break;
        else ifs = ifs->next;
    }
    if(ifs == NULL) return;
    else{
        packetN = (uint8_t*)malloc(length);
        
        //Ethernet head
        ethernets = (struct sr_ethernet_hdr*)packetN;
        memcpy(ethernets->ether_dhost, ((struct sr_ethernet_hdr*)packet)->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernets->ether_shost, ifs->addr, ETHER_ADDR_LEN);
        ethernets->ether_type = htons(ETHERTYPE_ARP);
        
        //ARP head
        arps = (struct sr_arphdr*)(packetN + sizeof(struct sr_ethernet_hdr));
        arps->ar_hrd = htons(ARPHDR_ETHER);
        arps->ar_pro = htons(ETHERTYPE_IP);
        arps->ar_hln = ETHER_ADDR_LEN;
        arps->ar_pln = 4;
        arps->ar_op = htons(ARP_REPLY);
        memcpy(arps->ar_sha, ifs->addr, ETHER_ADDR_LEN);
        arps->ar_sip = ifs->ip;
        memcpy(arps->ar_tha, ((struct sr_ethernet_hdr*)packet)->ether_shost, ETHER_ADDR_LEN);
        arps->ar_tip = ((struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr)))->ar_sip;
        
        sr_send_packet(sr, packetN, length, interface);
        
        //Update the ARP cache
        arp_cache_update(sr, interface, ethernets->ether_dhost, arps->ar_tip);
    }
}

/*---------------------------------------------------------------------
* Method: IPForwarding
*
*---------------------------------------------------------------------*/
void processIP(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int length){
    int etherhl = sizeof(struct sr_ethernet_hdr);
    int ipl = sizeof(struct ip);
    struct ip* ips;
    struct sr_rt* rts, *rtsd = NULL;
    struct sr_if* ifs;
    struct if_arp* arps;
    struct sr_ethernet_hdr* ethernets = (struct sr_ethernet_hdr*)packet;
    struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + etherhl + ipl);
    int byte_num = 0, i = 0;
    uint32_t check = 0, des_op = 0, mask_temp = 0, pwospf_check = 0;
    ips = (struct ip*)(packet + etherhl);
    byte_num = (ips->ip_hl) * 2;
//    if(ips->ip_p == IPPROTO_ICMP){
//        printf("Got it!\n");
//        int x = 0;
//        if(ips->ip_p == IPPROTO_ICMP){
//            printf("\n******************\n");
//            for(x = 0;x < length;x++){
//                printf("%x ", packet[x]);
//            }
//            printf("\n******************\n");
//        }
//    }
    //Wrong ip packet, drop
    if(ips->ip_v != 4) return;
    //incoming packet's TTL is one, drop
    if(ips->ip_ttl <= 1) return;
    
    //check sum
    for(i = 0;i < byte_num;i++){
        check += ntohs(*(uint16_t*)(packet+etherhl+i*2));
    }
    check = (check & 0xffff) + (check >> 16);
    
    //checksum fails
    if(check != 0xffff) return;
    
    //checksum sucesses
    rts = sr->routing_table;
    des_op = (ips->ip_dst).s_addr;
    
    //Update the ARP cache
    arp_cache_update(sr, interface, ethernets->ether_shost, (ips->ip_src).s_addr);
    
    //ospf packet
    if(ips->ip_p == 0x89){
        //version check
        if(ospf_hdr->version != OSPF_V2) return;
        
        //Area ID check
        if(ospf_hdr->aid != 0) return;
        
        //Authentication check
        if(ospf_hdr->audata != 0) return;
        
        //check sum evaluation
        for(i = 0;i < htons(ospf_hdr->len) / 2;i++){
            if(i <= 11 && i >= 8) pwospf_check += ntohs(*(uint16_t*)(packet+etherhl+ipl + i * 2));
        }
        pwospf_check = (check & 0xffff) + (check >> 16);
        //checksum fails
        if(pwospf_check != 0xffff) return;
        //hello message
        if(ospf_hdr->type == OSPF_TYPE_HELLO){
            ifs = sr->if_list;
           while(ifs != NULL){
               if(strcmp(ifs->name, interface) == 0) break;
               ifs = ifs->next;
           }
           //new neighbor
           if(ifs->neighbors == NULL){
               ifs->neighbors = (struct neighbor_router*)malloc(sizeof(struct neighbor_router));
           }
            ifs->neighbors->neighbor_RID = ospf_hdr->rid;
            ifs->neighbors->neighbor_IP = ips->ip_src.s_addr;
            ifs->neighbors->update_time = time(NULL);
        }
        //lsu message
        else if(ospf_hdr->type == OSPF_TYPE_LSU){
            LSU_process(sr, ospf_hdr, ips->ip_src.s_addr, packet, length, interface);
        }
        return;
    }
    
    ifs = sr->if_list;
    while(ifs != NULL){
        if(ifs->ip == des_op) break;
        ifs = ifs->next;
    }
    
    //If des_op is the address of the router
    if(ifs != NULL){
        
        //If the packet is ICMP
        if(ips->ip_p == IPPROTO_ICMP){
            //Check sum
//            check = 0;
//            //6 represents 6 uint_16 to be caculated.
//            for(i = 0;i < 6;i++){
//                check += ntohs(*(uint16_t*)(packet+etherhl+sizeof(struct ip)+i*2));
//            }
//            check = (check & 0xffff) + (check >> 16);
//            if(check != 0xffff) return;
//            printf("\n\n\n\nICMP\n\n\n\n");
            sendICMP(sr, packet, interface, length);
            return;
        }
        //TCP, UDP, ..
        else{
            //printf("\n\n\n\nTCP\n\n\\n\n");
            return;
        }
    }
    
    if(rts == NULL) return;       //Error, do nothing
    while(rts != NULL){
        if(((rts->dest).s_addr & (rts->mask).s_addr) ==
           (des_op & (rts->mask).s_addr) && rts->mask.s_addr >= mask_temp){
            mask_temp = rts->mask.s_addr;
            rtsd = rts;
        }
        rts = rts->next;
    }
    rts = rtsd;
    
    //find the interface structure
    ifs = sr->if_list;
    while(ifs != NULL){
        if(strcmp(ifs->name, rts->interface) == 0) break;
        ifs = ifs->next;
    }
    arps = ifs->arp_cache;
    while(arps != NULL){
        if(rts->gw.s_addr == 0){
            if(arps->p_addr == des_op) break;
        }
        else{
            if(arps->p_addr == rts->gw.s_addr) break;
        }
        arps = arps->next;
    }
    //ARP cache does not have the mac address, send ARP request, drop the IP packet.
    if(arps == NULL){
        sendARP(sr, rts->interface, rts->gw.s_addr, ips);
        add_unhandled(sr, packet, length);
        return;
    }
    //If the ARP entry has expired (15s)
    else if(time(NULL) - arps->created_time >= 15){
        //printf("\n\n-----------------TIME EXPIRE!---------------\n\n");
        sendARP(sr, rts->interface, rts->gw.s_addr, ips);
        add_unhandled(sr, packet, length);
        return;
    }
    //ARP cache has the mac address
    IPForwarding(sr, packet, arps->m_addr, ifs->addr, ifs->name, length);
}

/*---------------------------------------------------------------------
* Method: IPForwarding
*
*---------------------------------------------------------------------*/
void IPForwarding(struct sr_instance* sr, uint8_t* packet, unsigned char* macd, unsigned char* macs, char* interface, unsigned int length){
    uint8_t etherhl = sizeof(struct sr_ethernet_hdr);
    struct ip* ips = (struct ip*)(packet + etherhl);
    struct sr_ethernet_hdr* ethernets;
    ips->ip_ttl--;                 //update TTL
    //Calculate new checksum
    ips->ip_sum = 0;
    ips->ip_sum = calculate_checksum((uint8_t*)ips, ips->ip_hl);
    
    //Construct the new Ethernet packet
    ethernets = (struct sr_ethernet_hdr*)packet;
    memcpy(ethernets->ether_dhost, macd, ETHER_ADDR_LEN);
    memcpy(ethernets->ether_shost, macs, ETHER_ADDR_LEN);
    ethernets->ether_type = htons(ETHERTYPE_IP);
    //send the packet
    sr_send_packet(sr, packet, length, interface);
    
//    int x = 0;
//    if(ips->ip_p == IPPROTO_ICMP){
//        printf("\n******************\n");
//        for(x = 0;x < length;x++){
//            printf("%x ", packet[x]);
//        }
//        printf("\n******************\n");
//    }

}

/*---------------------------------------------------------------------
* Method: sendICMP
* uncheck ICMP check sum
*---------------------------------------------------------------------*/
void sendICMP(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int length){
    int ether_len = sizeof(struct sr_ethernet_hdr);
    int ip_len = sizeof(struct ip);
    struct sr_ethernet_hdr* ethernets = (struct sr_ethernet_hdr*)packet;
    struct ip* ips = (struct ip*)(packet + ether_len);
    uint8_t* ICMP_hdr;
    uint8_t ether_temp[ETHER_ADDR_LEN];
    uint32_t ip_temp;
    uint16_t*ICMP_checksum;
    //Exchange the ethernet address
    memcpy(ether_temp, ethernets->ether_dhost, ETHER_ADDR_LEN);
    memcpy(ethernets->ether_dhost, ethernets->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernets->ether_shost, ether_temp, ETHER_ADDR_LEN);
    
    //Exchange the ip address
    ip_temp = ips->ip_src.s_addr;
    ips->ip_src.s_addr = ips->ip_dst.s_addr;
    ips->ip_dst.s_addr = ip_temp;
    
    //Calculate ip checksum
    ips->ip_sum = 0;
    ips->ip_sum = calculate_checksum((uint8_t*)ips, ips->ip_hl);
    
    //Update ICMP part
    ICMP_hdr = packet + ether_len + ip_len;
    ICMP_hdr[0] = 0x0;        //set reply
    //calculate checksum
    ICMP_checksum = (uint16_t*)(ICMP_hdr+2);
    *ICMP_checksum = 0x0;
    *ICMP_checksum = calculate_checksum((uint8_t*)ICMP_hdr, 35);
    
    //send the packet
    sr_send_packet(sr, packet, length, interface);
}


/*---------------------------------------------------------------------
* Method: sendARP
*
*---------------------------------------------------------------------*/
void sendARP(struct sr_instance* sr, char* interface, uint32_t gw, struct ip* ips){
    struct sr_if* ifs;
    int i = 0;
    int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
    uint8_t* packet = (uint8_t*)malloc(len);
    struct sr_ethernet_hdr* ethernets = (struct sr_ethernet_hdr*)packet;
    struct sr_arphdr* arps = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
    
    ifs = sr->if_list;
    while(ifs != NULL){
        if(strcmp(ifs->name, interface) == 0) break;
        ifs = ifs->next;
    }
    if(ifs == NULL) return;
    
    //Build ethernet header
    for(i = 0;i < ETHER_ADDR_LEN;i++) ethernets->ether_dhost[i] = 0xff;
    memcpy(ethernets->ether_shost, ifs->addr, ETHER_ADDR_LEN);
    ethernets->ether_type = htons(ETHERTYPE_ARP);
    
    //Build arp header
    arps->ar_hrd = htons(0x1);
    arps->ar_pro = htons(ETHERTYPE_IP);
    arps->ar_hln = ETHER_ADDR_LEN;
    arps->ar_pln = 4;
    arps->ar_op = htons(ARP_REQUEST);
    memcpy(arps->ar_sha, ifs->addr, ETHER_ADDR_LEN);
    arps->ar_sip = ifs->ip;
    for(i = 0;i < ETHER_ADDR_LEN;i++) arps->ar_tha[i] = 0x0;
    if(gw == 0) arps->ar_tip = (ips->ip_dst).s_addr;
    else arps->ar_tip = gw;
    
//    int x = 0;
//    printf("\n*********************************\n");
//    for(x = 0;x < 42;x++){
//        printf("%x ", packet[x]);
//    }
//    printf("\n*********************************\n");
    
    //send the packet
    sr_send_packet(sr, packet, len, ifs->name);
}

/*---------------------------------------------------------------------
* Method: sr_arpapply
*
*---------------------------------------------------------------------*/
void sr_arpreply(struct sr_instance* sr, uint8_t* packet, char* interface, unsigned int length){
    struct sr_ethernet_hdr* ethernets;
    struct sr_arphdr* arph;
    struct ip* ipst;
    struct unhandled* un_packet, *prev;
    uint8_t mac[ETHER_ADDR_LEN];
    uint32_t ips;
    
    //Judge the length of the packet
    if(length != sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr)) return;
    
    ethernets = (struct sr_ethernet_hdr*)packet;
    memcpy(mac, ethernets->ether_shost, ETHER_ADDR_LEN);
    arph = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
    ips = arph->ar_sip;
    
    //update arp cache
    arp_cache_update(sr, interface, mac, ips);
    
    //Judge if forward IP packet
    un_packet = sr->un_packet;
    while(un_packet != NULL){
        ipst = (struct ip*)((un_packet->packet) + sizeof(struct sr_ethernet_hdr));
        if((ipst->ip_dst).s_addr == ips){
            IPForwarding(sr, un_packet->packet, ethernets->ether_shost, ethernets->ether_dhost, interface, un_packet->size);
            //Remove the first node
            if(un_packet == sr->un_packet){
                sr->un_packet = un_packet->next;
                free(un_packet);
                un_packet = sr->un_packet;
                continue;
            }
            else{
                prev->next = un_packet->next;
                free(un_packet);
                un_packet = prev->next;
                continue;
            }
        }
        else{
            prev = un_packet;
            un_packet = un_packet->next;
        }
    }
}

/*---------------------------------------------------------------------
* Method: arp_cache_update
*
*---------------------------------------------------------------------*/
void arp_cache_update(struct sr_instance* sr, char* interface, uint8_t* mac, uint32_t ips){
    struct if_arp* arps;
    struct sr_if* ifs = sr->if_list;
    while(ifs != NULL){
        if(strcmp(ifs->name, interface) == 0) break;
        ifs = ifs->next;
    }
    if(ifs == NULL) return;
    arps = ifs->arp_cache;
    if(arps == NULL){
        ifs->arp_cache = (struct if_arp*)malloc(sizeof(struct if_arp));
        arps = ifs->arp_cache;
    }
    else{
        while(arps->next != NULL){
            if(arps->p_addr == ips){
                memcpy(arps->m_addr, mac, ETHER_ADDR_LEN);
                arps->created_time = time(NULL);
                return;
            }
            arps = arps->next;
        }
        arps->next = (struct if_arp*)malloc(sizeof(struct if_arp));
        arps = arps->next;
    }
    memcpy(arps->m_addr, mac, ETHER_ADDR_LEN);
    arps->p_addr = ips;
    arps->created_time = time(NULL);
    arps->next = NULL;
    
//    printf("\nmac: ");
//    int x = 0;
//    for(x = 0;x < 6;x++) printf("%x ", ifs->arp_cache->m_addr[x]);
//    printf("\nip: %x", htonl(ifs->arp_cache->p_addr));
//    printf("\n next: %p", ifs->arp_cache->next);
//    printf("\n interface: %s", ifs->name);
}


/*---------------------------------------------------------------------
* Method: arp_cache_update
*
*---------------------------------------------------------------------*/
uint16_t calculate_checksum(uint8_t* start, unsigned long length){
    uint16_t* temp;
    uint32_t check = 0;
    int i = 0, byte_num = length * 2;
    for(i = 0;i < byte_num;i++){
        check += ntohs(*(uint16_t*)(start+i*2));
    }
    check = (check & 0xffff) + (check >> 16);
    //check = htonl(check);
    //memcpy(&(ips->ip_sum), &(check)+2, 2);
    temp = (uint16_t*)(&check);
    *temp = htons(*temp);
    *temp = (*temp) ^ 0xffff;
    return *temp;
}

void add_unhandled(struct sr_instance* sr, uint8_t* packet, unsigned long size){
    struct unhandled* un_packet = sr->un_packet;
    sr->un_packet = (struct unhandled*)malloc(sizeof(struct unhandled));
    sr->un_packet->packet = packet;
    sr->un_packet->size = size;
    sr->un_packet->next = un_packet;
}


/*---------------------------------------------------------------------
* Method: lsu process
*
*---------------------------------------------------------------------*/
void LSU_process(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr, uint32_t source, uint8_t *packet, int len, char* interface){
    struct sr_if* ifs = sr->if_list;
    struct seq_rt* s_rt = sr->s_rt;
    struct ospfv2_lsu_hdr* lsu_hdr = (struct ospfv2_lsu_hdr*)(((uint8_t*)ospf_hdr) + sizeof(struct ospfv2_hdr));
    //if from the source
    while(ifs != NULL){
        if(ifs->ip == source) return;
        ifs = ifs->next;
    }
    //sequence number judgement
    if(sr->s_rt == NULL){
        sr->s_rt = (struct seq_rt*)malloc(sizeof(struct seq_rt));
        sr->s_rt->RID = ospf_hdr->rid;
        sr->s_rt->sequence = lsu_hdr->seq;
        sr->s_rt->next = NULL;
        database_update(sr, ospf_hdr);
        forward_ospf(sr, packet, len, interface);
//        struct seq_rt* xiong = sr->s_rt;
//        printf("sequence: \n");
//        while(xiong != NULL){
//            printf("RID: %x   Sequence: %d\n", htonl(xiong->RID), htons(xiong->sequence));
//            xiong = xiong->next;
//        }
//        printf("end here!\n\n");
        
        return;
    }

    while(s_rt != NULL){
        if(s_rt->RID == ospf_hdr->rid){
            if(s_rt->sequence >= lsu_hdr->seq) return;
            else{
                s_rt->sequence = lsu_hdr->seq;
                database_update(sr, ospf_hdr);
                forward_ospf(sr, packet, len, interface);
                return;
            }
        }
        s_rt = s_rt->next;
    }
    //no sequence record, add the new one
    if(s_rt == NULL){
        s_rt = sr->s_rt;
        //Find the end of the list
        while(s_rt->next != NULL) s_rt = s_rt->next;
        s_rt->next = (struct seq_rt*)malloc(sizeof(struct seq_rt));
        s_rt->next->RID = ospf_hdr->rid;
        s_rt->next->sequence = lsu_hdr->seq;
        s_rt->next->next = NULL;
        database_update(sr, ospf_hdr);
        forward_ospf(sr, packet, len, interface);
        return;
    }
}

/*---------------------------------------------------------------------
* Method: Forwarding ospf
*
*---------------------------------------------------------------------*/
void forward_ospf(struct sr_instance* sr, uint8_t *packet, int len, char* interface){
    struct sr_if *ifs = sr->if_list;
    struct sr_ethernet_hdr* ethernet_hdr = (struct sr_ethernet_hdr*)packet;
    int i;
    while(ifs != NULL){
        if(strcmp(ifs->name, interface) != 0 && ifs->neighbors != NULL){
            for(i = 0;i < ETHER_ADDR_LEN;i++) ethernet_hdr->ether_dhost[i] = 0xff;
            memcpy(ethernet_hdr->ether_shost, ifs->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, ifs->name);
        }
        ifs = ifs->next;
    }
}

/*---------------------------------------------------------------------
* Method: database update
*
*---------------------------------------------------------------------*/
void database_update(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr){
    struct database* data_head = sr->db;
    struct database* db = sr->db;
    struct database_list* dbl = NULL;
    struct ospfv2_lsu_hdr* lsu_hdr = (struct ospfv2_lsu_hdr*)(((uint8_t*)ospf_hdr) + sizeof(struct ospfv2_hdr));
    uint32_t* data = (uint32_t*)(((uint8_t*)lsu_hdr) + sizeof(struct ospfv2_lsu_hdr));
    int i = 0, count = 0;
    while(db != NULL){
        //Entry exist, modify
        if(db->RID == ospf_hdr->rid){
            db->time = time(NULL);
            dbl = db->right;
            if(if_link_change(data_head, dbl, data, htonl(lsu_hdr->num_adv)) == 1){
                //printf("Not possible\n\n");
                router_table_update(sr);
            }
            break;
        }
        db = db->next;
    }
    //Entry do not exist, add.
    if(db == NULL){
        if(sr->db == NULL){
            sr->db = (struct database*)malloc(sizeof(struct database));
            db = sr->db;
            
        }
        else{
            db = sr->db;
            //find the end of the list
            while(db->next != NULL) db = db->next;
            db->next = (struct database*)malloc(sizeof(struct database));
            db = db->next;
            
        }
        
        db->RID = ospf_hdr->rid;
        db->time = time(NULL);
        db->next = NULL;
        db->right = NULL;
        if(htonl(lsu_hdr->num_adv) >= 1){
            db->right = (struct database_list*)malloc(sizeof(struct database_list));
            db->right->subnet = data[0];
            db->right->mask = data[1];
            db->right->RID = data[2];
            db->right->next = NULL;
            dbl = db->right;
            for(i = 0;i < htonl(lsu_hdr->num_adv) - 1;i++){
                dbl->next =(struct database_list*)malloc(sizeof(struct database_list));
                dbl->next->subnet = data[(i+1)*3];
                dbl->next->mask = data[(i+1)*3 + 1];
                dbl->next->RID = data[(i+1)*3 + 2];
                dbl->next->next = NULL;
                dbl = dbl->next;
            }
        }
        db = sr->db;
        while(db != NULL){
            count++;
            db = db->next;
        }
        //Have all three entries in the database
        if(count == 3){
            router_table_update(sr);
        }
    }

    
//    struct database* xiong = sr->db;
//    struct database_list* yu = NULL;
//    printf("adjacency table: \n");
//    while(xiong != NULL){
//        printf("RID: %x time: %d", htonl(xiong->RID), xiong->time);
//        yu = xiong->right;
//        while(yu != NULL){
//            printf(" RID: %x", htonl(yu->RID));
//            printf(" Subnet: %x", htonl(yu->subnet));
//            printf(" Mask: %x\n", htonl(yu->mask));
//            yu = yu->next;
//        }
//        printf("\n");
//        xiong = xiong->next;
//    }
//    printf("aj ends here!\n");
}

/*---------------------------------------------------------------------
* Method: router table update
*
*---------------------------------------------------------------------*/
void router_table_update(struct sr_instance* sr){
//    printf("-------------The original routing table----------\n");
//    sr_print_routing_table(sr);
    struct sr_rt* rt;
    struct database* db;
    struct database_list* dbl;
    struct sr_if* ifs = sr->if_list;
    uint32_t RID_arr[2] = {-1, -1};
    int count = 0;
    int i = 0, flag = 0;
    clear_router_table(sr);
    rt = sr->routing_table;
    db = find_database_entry(sr->db, sr->RID);
    dbl = db->right;
    //Not the first router
    if(rt == NULL){
        while(dbl != NULL){
            if(dbl->RID == 0 && host_type(sr, dbl) == 1){
                sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
                rt = sr->routing_table;
                rt->dest = construct_in_addr(dbl->subnet);
                rt->mask = construct_in_addr(dbl->mask);
                ifs = update_table_find_interface(sr, dbl->subnet, dbl->mask);
                rt->gw = construct_in_addr(0);
                strncpy(rt->interface, ifs->name, SR_IFACE_NAMELEN);
            }
            dbl = dbl->next;
        }
        dbl = db->right;
        //Add the default path
        add_default_path(sr, &rt);
    }
    //Three adjacentcies
    while(dbl != NULL){
        if(dbl->RID != 0){
            //Find the interface
            ifs = update_table_find_interface(sr, dbl->subnet, dbl->mask);
            if(ifs->neighbors == NULL) return;
            rt->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
            rt = rt->next;
            rt->dest = construct_in_addr(dbl->subnet);
            rt->mask = construct_in_addr(dbl->mask);
            rt->gw = construct_in_addr(ifs->neighbors->neighbor_IP);
            RID_arr[count++] = dbl->RID;
            strncpy(rt->interface, ifs->name, SR_IFACE_NAMELEN);
        }
        dbl = dbl->next;
    }
    //two outers
    for(i = 0;i < 2;i++){
        if(RID_arr[i] != -1){
            db = find_database_entry(sr->db, RID_arr[i]);
            dbl = db->right;
            while(dbl != NULL){
                //visited
                if(judge_visited(RID_arr, dbl->RID, sr) == 1) {
                    dbl = dbl->next;
                    continue;
                }
                else{
                    if(dbl->RID != 0){
                        flag = 1;
                        RID_arr[count++] = dbl->RID;
                    }
                    rt->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
                    rt = rt->next;
                    rt->dest = construct_in_addr(dbl->subnet);
                    rt->mask = construct_in_addr(dbl->mask);
                    if(flag == 0) ifs = table_find_interface_RID(sr, RID_arr[i]);
                    else ifs = table_find_interface_RID(sr, RID_arr[0]);
                    rt->gw = construct_in_addr(ifs->neighbors->neighbor_IP);
                    strncpy(rt->interface, ifs->name, SR_IFACE_NAMELEN);
                    dbl = dbl->next;
                    
                }
            }
        }
    }
    printf("----------The modified routing table----------\n");
    sr_print_routing_table(sr);
}

struct in_addr construct_in_addr(uint32_t value){
    struct in_addr *temp = (struct in_addr*)malloc(sizeof(struct in_addr));
    temp->s_addr = value;
    return *temp;
}

struct sr_if* update_table_find_interface(struct sr_instance* sr, uint32_t subnet, uint32_t mask){
    struct sr_if* ifs = sr->if_list;
    while(ifs != NULL){
        if(((ifs->ip) & (ifs->mask)) == (subnet & mask)) return ifs;
        ifs = ifs->next;
    }
    //Never happens
    return NULL;
}

struct sr_if* table_find_interface_RID(struct sr_instance* sr, uint32_t RID){
    struct sr_if* ifs = sr->if_list;
    while(ifs != NULL){
        if(ifs->neighbors != NULL && ifs->neighbors->neighbor_RID == RID) return ifs;
        ifs = ifs->next;
    }
    return NULL;
}

struct database* find_database_entry(struct database* db,  uint32_t RID){
    struct database* temp = db;
    while(temp != NULL){
        if(temp->RID == RID) return temp;
        temp = temp->next;
    }
    return NULL;
}

int judge_visited(uint32_t RID_arr[], uint32_t RID, struct sr_instance* sr){
    int i = 0;
    if(RID == 0) return 0;
    for(i = 0;i < 2;i++){
        if(RID_arr[i] == RID) return 1;
    }
    if(sr->RID == RID) return 1;
    return 0;
}

void add_default_path(struct sr_instance* sr, struct sr_rt** rt){
    struct sr_if* ifs = sr->if_list;
    (*rt)->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    (*rt) = (*rt)->next;
    while(ifs != NULL){
        if(strcmp(ifs->name, "eth0") == 0) break;
        ifs = ifs->next;
    }
    if(ifs->neighbors == NULL){
        ifs = sr->if_list;
        while(ifs != NULL){
            if(ifs->neighbors != NULL) break;
            ifs = ifs->next;
        }
        if(ifs == NULL) return;
    }
    (*rt)->dest = construct_in_addr(0);
    (*rt)->mask = construct_in_addr(0);
    (*rt)->gw = construct_in_addr(ifs->neighbors->neighbor_IP);
    strncpy((*rt)->interface, ifs->name, SR_IFACE_NAMELEN);
}

int if_link_change(struct database* db, struct database_list* dbl, uint32_t* data, int size){
    int i = 0, flag = 0, count = 0;
    while(dbl != NULL){
        for(i = 0;i < size;i++){
            if((dbl->subnet & dbl->mask) == (data[3*i+0] & data[3*i+1]) && dbl->RID != data[3*i+2]){
                dbl->RID = data[3*i+2];
                flag = 1;
            }
        }
        dbl = dbl->next;
    }
    while(db != NULL){
        db = db->next;
        count++;
    }
    if(count != 3) return 0;
    return flag;
}

void clear_router_table(struct sr_instance* sr){
    struct sr_rt *rt = sr->routing_table;
    if(rt == NULL) return;
    if(rt->dest.s_addr == 0) rt->next = NULL;
    else sr->routing_table = NULL;
}

//1 for server, 0 for unconnected
int host_type(struct sr_instance *sr, struct database_list *dbl){
    struct database_list *temp;
    struct database* db = sr->db;
    while(db != NULL){
        temp = db->right;
        while(temp != NULL){
            if(temp != dbl && (temp->subnet & temp->mask) == (dbl->subnet & dbl->mask)) return 0;
            temp = temp->next;
        }
        db = db->next;
    }
    return 1;
}
