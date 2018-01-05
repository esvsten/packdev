#ifndef PACKDEV_SPD_CONFIG_H_
#define PACKDEV_SPD_CONFIG_H_

#define SPD_CONTEXT_NAME "packdev-spd-ipv4"

typedef enum {
    PACKDEV_SPD_PROTECT,
    PACKDEV_SPD_DISCARD,
    PACKDEV_SPD_BYPASS,
    PACKDEV_SPD_MAX
} packdev_spd_result_t;

typedef struct {
    uint32_t             policy_id;
    uint32_t             sa_id;
    packdev_spd_result_t action;
} packdev_policy_t;

static inline packdev_spd_result_t packdev_spd_get_action(const char *action_string) {
    if (strncmp("PROTECT", action_string, strlen("PROTECT")) == 0) {
        return PACKDEV_SPD_PROTECT;
    } else if (strncmp("DISCARD", action_string, strlen("DISCARD")) == 0) {
        return PACKDEV_SPD_DISCARD;
    } else if (strncmp("BYPASS", action_string, strlen("BYPASS")) == 0) {
        return PACKDEV_SPD_BYPASS;
    }

    return PACKDEV_SPD_MAX;
}

struct rte_acl_ctx* packdev_spd_config_get_context();

packdev_policy_t* packdev_spd_config_get(uint32_t policy_id);

#endif /* PACKDEV_SPD_CONFIG_H_ */
