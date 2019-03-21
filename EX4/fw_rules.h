#ifndef FW_RULES_H
#define FW_RULES_H
#include "fw.h"
#include "list.h"
#include "fw_log.h"
#include "conn_table.h"

#define IS_LOCALHOST(x) (x > 2130706431U && x < 2147483648U)

unsigned int hook_func(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *));

unsigned int hook_func_local_in(unsigned int hooknum, 
								struct sk_buff *skb, 
								const struct net_device *in, 
								const struct net_device *out, 
								int (*okfn)(struct sk_buff *));

unsigned int hook_func_local_out(unsigned int hooknum, 
								struct sk_buff *skb, 
								const struct net_device *in, 
								const struct net_device *out, 
								int (*okfn)(struct sk_buff *));

void redirect_out(struct sk_buff *skb);
void redirect_in(struct sk_buff *skb);

int compare_to_rule(struct sk_buff* skb,rule_t* rule,direction_t dir);

unsigned int is_xmas(struct tcphdr* tcph);

void print_rules(void);

int compare_pkt_against_rules(struct sk_buff* skb,direction_t dir);

decision_t* inspect_pkt(struct sk_buff *skb,direction_t dir);

int append_rule(rule_t* rule);

void add_localhost(void);

void add_prot_other(void);

void clear_rules(void);

int string_to_ip(char** ip_string,unsigned int* ip,unsigned int* mask,unsigned int* mask_size);

int parse_protocol(char* prot,rule_t* rule);

int parse_port(char* port, rule_t* rule,int flag);

int parse_rule_string(char* rule_string,rule_t* rule);

log_row_t* create_log(struct sk_buff* skb,decision_t* res,unsigned char hooknum);

ssize_t size_show(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t active_show(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t active_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

ssize_t rule_store(struct device *dev,struct device_attribute *attr,const char* buf,size_t count);

ssize_t clear_rules_store(struct device *dev,struct device_attribute *attr,const char* buf,size_t count);

ssize_t set_cur_rule(struct device *dev,struct device_attribute *attr,const char* buf,size_t count);

ssize_t get_rule(struct device *dev, struct device_attribute *attr, char *buf);

#endif