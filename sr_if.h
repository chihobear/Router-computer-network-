/*-----------------------------------------------------------------------------
 * file:  sr_if.h
 * date:  Sun Oct 06 14:13:13 PDT 2002 
 * Contact: casado@stanford.edu 
 *
 * Description:
 *
 * Data structures and methods for handeling interfaces
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_INTERFACE_H
#define sr_INTERFACE_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#define SR_IFACE_NAMELEN 32

struct sr_instance;

/* ----------------------------------------------------------------------------
 * struct sr_if
 *
 * Node in the interface list for each router
 *
 * -------------------------------------------------------------------------- */

struct if_arp
{
    unsigned char m_addr[6];
    unsigned long p_addr;
    struct if_arp* next;
    time_t created_time;
};

struct neighbor_router
{
    uint32_t neighbor_RID;
    uint32_t neighbor_IP;
    time_t update_time;
};

struct sr_if
{
    char name[SR_IFACE_NAMELEN];
    unsigned char addr[6];
    uint32_t ip;
    uint32_t speed;
    struct if_arp* arp_cache;
    uint32_t mask;
    uint16_t helloint;
    struct neighbor_router* neighbors;
    struct sr_if* next;
};

struct sr_if* sr_get_interface(struct sr_instance* sr, const char* name);
void sr_add_interface(struct sr_instance*, const char*);
void sr_set_ether_addr(struct sr_instance*, const unsigned char*);
void sr_set_ether_ip(struct sr_instance*, uint32_t ip_nbo);
void sr_set_ether_mask(struct sr_instance*, uint32_t ip_nbo);
void sr_print_if_list(struct sr_instance*);
void sr_print_if(struct sr_if*);

#endif /* --  sr_INTERFACE_H -- */
