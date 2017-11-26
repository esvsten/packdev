#ifndef PACKDEV_ESP_H_
#define PACKDEV_ESP_H_

#include <rte_mbuf.h>

void packdev_esp_process(struct rte_mbuf *packet);

#endif /* PACKDEV_ESP_H_ */
