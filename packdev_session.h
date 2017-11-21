#ifndef PACKDEV_SESSION_H_
#define PACKDEV_SESSION_H_

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_table.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#define SESSION_IV 123

typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
} ipv4_session_config_t;

void packdev_session_init();

struct rte_hash* packdev_session_get_table();

#endif /* PACKDEV_SESSION_H_ */
