/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include<stdint.h>
#include <pthread.h>

/* forward declare */
struct sr_instance;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */


    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_t thread_LSU;
    pthread_mutex_t lock_LSU;
};

int pwospf_init(struct sr_instance* sr);
void send_hello(struct sr_instance *sr);
void send_LSU(struct sr_instance* sr);
uint16_t ospf_checksum(uint8_t* start, unsigned long length);
void clear_hello_result(struct sr_instance *sr);

#endif /* SR_PWOSPF_H */
