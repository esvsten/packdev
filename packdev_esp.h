#ifndef PACKDEV_ESP_H_
#define PACKDEV_ESP_H_

#include <rte_mbuf.h>

void packdev_esp_process(
        struct rte_mbuf *packet,
        uint16_t port_id);

#endif /* PACKDEV_ESP_H_ */
