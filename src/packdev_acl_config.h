#ifndef PACKDEV_ACL_CONFIG_H_
#define PACKDEV_ACL_CONFIG_H_

#include "rte_acl.h"

#define ACL_CONTEXT_NAME "packdev-acl-ipv4"

typedef enum {
    PACKDEV_ACL_NO_MATCH,
    PACKDEV_ACL_ACCEPT,
    PACKDEV_ACL_DENY,
    PACKDEV_ACL_MAX
} packdev_acl_result_t;

static inline packdev_acl_result_t packdev_acl_get_action(const char *action_string) {
    if (strncmp("ACCEPT", action_string, strlen("ACCEPT")) == 0) {
        return PACKDEV_ACL_DENY;
    } else if (strncmp("DENY", action_string, strlen("DENY")) == 0) {
        return PACKDEV_ACL_DENY;
    }

    return PACKDEV_ACL_NO_MATCH;
}
struct rte_acl_ctx* packdev_acl_config_get_context();

#endif /* PACKDEV_ACL_CONFIG_H_ */
