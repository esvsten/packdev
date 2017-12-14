#ifndef PACKDEV_PACKET_H_
#define PACKDEV_PACKET_H_

#include <rte_mbuf.h>

void packdev_packet_receive(
        uint8_t port_id,
        uint16_t queue_id,
        struct rte_mbuf *pkts[],
        uint16_t max_num_pkts);

void packdev_packet_send(
        struct rte_mbuf *packet,
        uint8_t port_id,
        uint16_t queue_id);

void packdev_packet_flush_all(uint8_t port_id);

#endif // PACKDEV_PACKET_H_
