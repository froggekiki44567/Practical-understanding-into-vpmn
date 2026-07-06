#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H

#include <stdint.h>

#define MAX_RULES 64

typedef enum {RULE_ALLOW, RULE_DENY} rule_action_t;

# Structure that saves one firewall rule
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    rule_action_t action;
} fw_rule_t;

# Structure that saves how many rules are in the firewall togerher with the default action
typedef struct {
    fw_rule_t rules[MAX_RULES];
    int count;
    rule_action_t default_action;
} firewall_t;

# Firewall main functions that will be used
void fw_init(firewall_t *fw, rule_action_t default_action);
int fw_add_rule(firewall_t *fw, const char *cidr, uint16_t port, rule_action_t action);
int fw_check(const firewall_t *fw, const unsigned char *packet, int len);

#endif // PACKET_FILTER_H
