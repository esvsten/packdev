#ifndef PACKDEV_SESSION_H_
#define PACKDEV_SESSION_H_

#include "rte_acl.h"

#define SESSION_CONTEXT_NAME "packdev-session-ipv4"

typedef enum {
    PACKDEV_SESSION_NO_MATCH,
    PACKDEV_SESSION_SEND_TO_FP,
    PACKDEV_SESSION_SEND_TO_CPU,
    PACKDEV_SESSION_MAX
} packdev_session_result_t;

static inline packdev_session_result_t packdev_session_get_action(const char *action_string) {
    if (strncmp("SEND_TO_FP", action_string, strlen("SEND_TO_FP")) == 0) {
        return PACKDEV_SESSION_SEND_TO_FP;
    } else if (strncmp("SEND_TO_CPU", action_string, strlen("SEND_TO_CPU")) == 0) {
        return PACKDEV_SESSION_SEND_TO_CPU;
    }

    return PACKDEV_SESSION_NO_MATCH;
}

struct rte_acl_ctx* packdev_session_config_get_context();

#endif /* PACKDEV_SESSION_H_ */
