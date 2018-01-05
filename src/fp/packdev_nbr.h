#ifndef PACKDEV_NBR_H_
#define PACKDEV_NBR_H_

#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_ether.h>

#define NBR_TABLE_IV 127

typedef enum {
    PACKDEV_ARP_INVALID,
    PACKDEV_ARP_INCOMPLETE,
    PACKDEV_ARP_VALID,
    PACKDEV_ARP_STALE,
    PACKDEV_ARP_MAX
} packdev_arp_state_t;

typedef struct {
    uint32_t nbr_id;
    uint32_t ipv4_addr;
    uint8_t mac_addr[6];
    uint32_t state;
    uint32_t origin;
} packdev_nbr_t;

void packdev_nbr_init();

void packdev_l2_nbr_add(
        uint32_t ipv4_addr,
        uint8_t mac_addr[6],
        uint32_t origin);

packdev_nbr_t* packdev_l2_nbr_get(uint32_t ipv4_addr);

void packdev_l2_nbr_set_state(
        uint32_t ipv4_addr,
        uint8_t mac_addr[ETHER_ADDR_LEN],
        uint32_t state);

void packdev_l2_nbr_rem(
        uint32_t ipv4_addr);

#endif /* PACKDEV_NBR_H_ */

