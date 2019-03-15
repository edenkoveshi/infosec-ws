#include "fw_rules.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eden Koveshi");

/*static struct file_operations fops = {
	.owner = THIS_MODULE,
};*/

static unsigned int is_active = 1;
static rule_t* rules[MAX_RULES+2]; //one for localhost,one for PROT_OTHER
static unsigned int num_rules = 0;
//static DEFINE_SPINLOCK(xxx_lock);
static unsigned int cur_rule = 0;

ssize_t active_show(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, 3,"%u\n",is_active);
}

ssize_t active_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;

	if (sscanf(buf, "%u", &temp) == 1)
	{
		if(temp == 0) is_active = 0;
		else if(temp == 1) is_active = 1;
	}

	return count;
}

int compare_to_rule(struct sk_buff* skb,rule_t* rule,direction_t dir){
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	prot_t protocol;
	ack_t  ack = ACK_ANY;
	struct iphdr* iph;
	struct tcphdr* tcph;
	struct udphdr* udph;
	int tcp = 0;
	int udp = 0;

	printk(KERN_INFO "****rule:%s****",rule->rule_name);

	iph = (struct iphdr*)skb_network_header(skb); //construct ip header of hooked pkt

	if(!iph) return ERROR;

	src_ip = ntohl(iph->saddr);
	if((src_ip & rule->src_prefix_mask) != (rule->src_ip & rule->src_prefix_mask)) return NO_MATCH;

	//printk(KERN_INFO "*** src ip matches ***");

	dst_ip = ntohl(iph->daddr);
	if((dst_ip & rule->dst_prefix_mask) != (rule->dst_ip & rule->dst_prefix_mask)) return NO_MATCH;

	//printk(KERN_INFO "*** dst ip matches ***");

	if(dir != rule->direction && rule->direction != DIRECTION_ANY && dir != DIRECTION_ANY) return NO_MATCH;

	//printk(KERN_INFO "*** dir matches ***");

	if(iph->protocol != PROT_ICMP && iph->protocol != PROT_UDP && iph->protocol != PROT_TCP) protocol = PROT_OTHER;
	else protocol = iph->protocol;
	if(protocol != rule->protocol && rule->protocol != PROT_ANY) return NO_MATCH;

	//printk(KERN_INFO "*** protocol matches ***");

	switch(protocol){
		case PROT_TCP:
			tcph = (struct tcphdr*)((char*)iph + (iph->ihl * 4));
			if(!tcph) return ERROR;
			src_port = ntohs(tcph->source);
			dst_port = ntohs(tcph->dest);
			ack = tcph->ack;
			tcp = 1;
			break;
		case PROT_UDP:
			udph = (struct udphdr*)(skb_transport_header(skb)+20); //http://www.roman10.net/2011/07/23/how-to-filter-network-packets-using-netfilterpart-2-implement-the-hook-function/
			if(!udph) return ERROR;
			src_port = ntohs(udph->source);
			dst_port = ntohs(udph->dest);
			udp = 1;
			break;
		default:
			break;
	}

	
	if((tcp || udp) && src_port != rule->src_port && (rule->src_port != PORT_ABOVE_1023 || src_port < PORT_ABOVE_1023) && rule->src_port != 0) return NO_MATCH;

	//printk(KERN_INFO "*** src port matches ***");

	if((tcp || udp) && dst_port != rule->dst_port && (rule->dst_port != PORT_ABOVE_1023 || dst_port < PORT_ABOVE_1023) && rule->dst_port != 0) return NO_MATCH;	 

	//printk(KERN_INFO " *** dst port matches ***");
	
	if(tcp && (ack & rule->ack) != 0) return NO_MATCH;
	
	//printk(KERN_INFO "*** ack matches***");

	return SUCCESS;
}

unsigned int is_xmas(struct tcphdr* tcph){
	if(!tcph) return 0;
	return (tcph->psh && tcph->fin && tcph->urg);
}

int compare_pkt_against_rules(struct sk_buff* skb,direction_t dir){
	int i;
	int comp;
	/*decision_t* res;
	res = kmalloc(sizeof(decision_t),GFP_ATOMIC);
	if(!res) return NULL;*/

	for(i=0;i<num_rules;i++){
		comp = compare_to_rule(skb,rules[i],dir);
		if(comp == SUCCESS){ 
			return i;
		}
		else if(comp == ERROR){
			return REASON_ILLEGAL_VALUE;
		}
	}
	return REASON_NO_MATCHING_RULE;
}

int append_rule(rule_t* rule){
	if(num_rules > MAX_RULES + 1) return ERROR;
	if(!rule) return ERROR;
	rules[num_rules] = rule;
	num_rules++;
	return SUCCESS;
}

void add_localhost(void){
	rule_t* localhost;
	localhost = kmalloc(sizeof(rule_t),GFP_ATOMIC);
	strncpy(localhost->rule_name,"localhost",20);
	localhost->direction = DIRECTION_ANY;
	localhost->src_ip = 0x7f000001;
	localhost->src_prefix_mask = 0xff000000;
	localhost->src_prefix_size = 8;
	localhost->dst_ip = 0x7f000001;
	localhost->dst_prefix_mask = 0xff000000;
	localhost->dst_prefix_size = 8;
	localhost->src_port = 0;
	localhost->dst_port = 0;
	localhost->protocol = PROT_ANY;
	localhost->ack = ACK_ANY;
	localhost->action = NF_ACCEPT;
	append_rule(localhost);
}

void add_prot_other(void){
	rule_t* prot_other = kmalloc(sizeof(rule_t),GFP_ATOMIC);
	strncpy(prot_other->rule_name,"PROT_OTHER",20);
	prot_other->direction = DIRECTION_ANY;
	prot_other->src_ip = 0x0000000;
	prot_other->src_prefix_mask = 0x00000000;
	prot_other->src_prefix_size = 0;
	prot_other->dst_ip = 0x00000000;
	prot_other->dst_prefix_mask = 0x00000000;
	prot_other->dst_prefix_size = 0;
	prot_other->src_port = 0;
	prot_other->dst_port = 0;
	prot_other->protocol = PROT_OTHER;
	prot_other->ack = ACK_ANY;
	prot_other->action = NF_ACCEPT;
	append_rule(prot_other);
}

void clear_rules(void){
	int i;
	for(i=0;i<num_rules;i++){
		kfree(rules[i]);
	}
	num_rules = 0;
	cur_rule = 0;
}

int string_to_ip(char** ip_string,unsigned int* ip,unsigned int* mask,unsigned int* mask_size){
	char* byte;
	int i = 3;
	int temp;
	char* t;
	char* mask_string;

	*ip = 0;
	*mask = 0;
	*mask_size = 0;

	t = strsep(ip_string,"/");
	if(t == NULL) return ERROR;
	mask_string = strsep(ip_string,"/");
	if(mask_string == NULL) return ERROR;
	if(kstrtouint(mask_string,0,mask_size) != 0) return ERROR;
	if(*mask_size < 0 || *mask_size > 32) return ERROR;

	while(i>=0){
		byte = strsep(&t,".");
		if(byte == NULL) return ERROR;
		if(kstrtouint(byte,0,&temp) != 0) return ERROR;
		if(temp < 0 || temp > 255) return ERROR;
		*ip += (temp << i*8);
		i-=1;
	}

	if(strsep(&t,".") != NULL) return ERROR;

	*mask = 0xffffffff << (32-*mask_size);

	return SUCCESS;
}


int parse_protocol(char* prot,rule_t* rule){
	if(strcmp(prot,"TCP") == 0) rule->protocol = PROT_TCP;
	else if(strcmp(prot,"UDP") == 0) rule->protocol = PROT_UDP;
	else if(strcmp(prot,"ICMP") == 0) rule->protocol = PROT_ICMP;
	else if (strcmp(prot,"any") == 0) rule->protocol = PROT_ANY;
	else return ERROR;
	return SUCCESS;
}


int parse_port(char* port, rule_t* rule,int flag){
	int p;

	if(strcmp(port,"any") == 0){
		if(flag) rule->dst_port = PORT_ANY;
		else rule->src_port = PORT_ANY;
		return SUCCESS;
	}

	if(strcmp(port,">1023")== 0 || strcmp(port,"1023") == 0){
		if(flag) rule->dst_port = PORT_ABOVE_1023;
		else rule->src_port = PORT_ABOVE_1023;
		return SUCCESS;
	}

	if(kstrtoint(port,10,&p) != 0) return ERROR;
	if(p > 1023 || p < 0) return ERROR;
	if(flag) rule->dst_port = (__be16)p;
	else rule->src_port = (__be16)p;
	return SUCCESS;
}

int parse_rule_string(char* rule_string,rule_t* rule){
	char* field;
	char* rest = rule_string;
	int space_ctr = 0;
	int src_ip = 0;
	int dst_ip = 0;
	int src_mask= 0;
	int dst_mask = 0;
	int src_size = 0;
	int dst_size = 0;

	if(!rule){
		printk(KERN_ALERT "rule is null");
		return ERROR;
	}

	if(!rule_string){
		printk(KERN_ALERT "rule_string is null");
		return ERROR;
	}


	while((field = strsep(&rest," ")) !=NULL){
		switch(space_ctr){
			case 0:
				if(strlen(field) > 20) return ERROR;
				memset(rule->rule_name,0,20);
				strncpy(rule->rule_name,field,strlen(field));
				if(rule->rule_name == NULL) return ERROR;
				printk(KERN_INFO "RULE NAME:%s",rule->rule_name);
				break;
			case 1:
				if(strcmp(field,"in") == 0) rule->direction = DIRECTION_IN;
				else if(strcmp(field,"out") == 0) rule->direction = DIRECTION_OUT;
				else if(strcmp(field,"any") == 0) rule->direction = DIRECTION_ANY;
				else return ERROR;
				break;
			case 2:
				if(strcmp(field,"any") == 0){
					rule->src_ip = 0x00000000;
					rule->src_prefix_mask = 0x00000000;
					rule->src_prefix_size = 0;
				}
				else if(string_to_ip(&field,&src_ip,&src_mask,&src_size) != ERROR){
					rule->src_ip = src_ip;
					rule->src_prefix_mask = src_mask;
					rule->src_prefix_size = src_size;
				}
				else return ERROR;
				break;
			case 3:
				if(strcmp(field,"any") == 0){
					rule->dst_ip = 0x00000000;
					rule->dst_prefix_mask = 0x00000000;
					rule->dst_prefix_size = 0;
				}
				else if(string_to_ip(&field,&dst_ip,&dst_mask,&dst_size) != ERROR){
					rule->dst_ip = dst_ip;
					rule->dst_prefix_mask = dst_mask;
					rule->dst_prefix_size = dst_size;
				}
				else return ERROR;
				break;
			case 4:
				if(parse_protocol(field,rule) == ERROR) return ERROR;
				break;
			case 5:
				if(parse_port(field,rule,0) == ERROR) return ERROR;
				break;
			case 6:
				if(parse_port(field,rule,1) == ERROR) return ERROR;
				break;
			case 7:
				if(strcmp(field,"yes") == 0) rule->ack = ACK_YES;
				else if(strcmp(field,"no") == 0) rule->ack = ACK_NO;
				else if(strcmp(field,"any") == 0) rule->ack = ACK_ANY;
				else return ERROR;
				break;
			case 8:
				if(strncmp(field,"accept",6) == 0) rule->action = NF_ACCEPT;
				else if(strncmp(field,"drop",4) == 0) rule->action = NF_DROP;
				else return ERROR;
				break;
			default: 
				return ERROR;
		}
		space_ctr++;
	}

	if(space_ctr < 8) return ERROR;
	return SUCCESS;
}

log_row_t* create_log(struct sk_buff* skb,decision_t* res,unsigned char hooknum){
	log_row_t* log;
	struct iphdr* iph;
	struct tcphdr* tcph;
	struct udphdr* udph;
	prot_t protocol;
	struct timeval tv;

	if(!skb) return NULL;
	if(!res) return NULL;

	log = kmalloc(sizeof(log_row_t),GFP_ATOMIC);
	if(!log) return NULL;

	iph = (struct iphdr*)skb_network_header(skb); //construct ip header of hooked pkt
	if(!iph){
		kfree(log);
		return NULL;
	}

	log->src_ip = ntohl(iph->saddr);
	log->dst_ip = ntohl(iph->daddr);
	printk(KERN_INFO "src_ip:%u dst_ip:%u",log->src_ip,log->dst_ip);

	if(iph->protocol != PROT_ICMP && iph->protocol != PROT_UDP && iph->protocol != PROT_TCP) protocol = PROT_OTHER;
	else protocol = iph->protocol;

	log->protocol = protocol;

	if(protocol == PROT_TCP){
		tcph = (struct tcphdr*)((char*)iph + (iph->ihl * 4));
		if(!tcph){
			kfree(log);
			return NULL;
		}
		log->src_port = ntohs(tcph->source);
		log->dst_port = ntohs(tcph->dest);
	}
	else if(protocol == PROT_UDP){
		udph = (struct udphdr *)(skb_transport_header(skb)+20);
		if(!udph){
			kfree(log);
			return NULL;
		}
		log->src_port = ntohs(udph->source);
		log->dst_port = ntohs(udph->dest);
	}
	else{
		log->src_port = 0;
		log->dst_port = 0;
	}

	log->action = res->action;
	log->reason = res->reason;
	/*memcpy(&log->action,&res->action,sizeof(unsigned int));
	memcpy(&log->reason,&res->reason,sizeof(int));*/
	log->hooknum = hooknum;

	do_gettimeofday(&tv);

	log->timestamp = tv.tv_sec;

	return log;
}




ssize_t size_show(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, sizeof(unsigned int), "%u",num_rules);
}

ssize_t rule_store(struct device *dev,struct device_attribute *attr,const char* buf,size_t count){
	char* rule_string;
	rule_t* rule = kmalloc(sizeof(rule_t),GFP_ATOMIC);
	rule_string = kmalloc(MAX_RULE_STRING_SIZE,GFP_ATOMIC);
	if (strncpy(rule_string,buf,MAX_RULE_STRING_SIZE))
	{
		if(parse_rule_string(rule_string,rule) == ERROR){ 
			kfree(rule_string);
			kfree(rule);
			printk(KERN_INFO "parse_rule_string returned ERROR!");
			clear_rules();
			return ERROR;
		}
		if(append_rule(rule) == ERROR) {
			kfree(rule_string);
			kfree(rule);
			printk(KERN_INFO "append_rule retuend ERROR");
			clear_rules();
			return ERROR;
		}
	}
	kfree(rule_string);
	return count;
}

ssize_t clear_rules_store(struct device *dev,struct device_attribute *attr,const char* buf,size_t count){
	clear_rules();
	return count;
}


ssize_t set_cur_rule(struct device *dev,struct device_attribute *attr,const char* buf,size_t count){
	unsigned int temp;

	if (sscanf(buf, "%u", &temp) == 1)
	{
		cur_rule = temp;
	}

	return count;
}

ssize_t get_rule(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	rule_t* rule = rules[cur_rule];
	char rule_string[MAX_RULE_STRING_SIZE] = {0};
	char direction[4] = {0};
	char* src_ip;
	char* dst_ip;
	char src_mask[3] = {0};
	char dst_mask[3] = {0};
	char protocol[6] = {0};
	char src_port[6] = {0};
	char dst_port[6] = {0};
	char ack[4] = {0};
	char action[7] = {0};

	switch(rule->direction){
		case DIRECTION_IN:
			strcpy(direction,"in");
			break;
		case DIRECTION_OUT:
			strcpy(direction,"out");
			break;
		case DIRECTION_ANY:
			strcpy(direction,"any");
			break;
		default:
			return scnprintf(buf,5,"%s","ERROR");
	}

	switch(rule->protocol){
		case PROT_TCP:
			strcpy(protocol,"TCP");
			break;
		case PROT_UDP:
			strcpy(protocol,"UDP");
			break;
		case PROT_ICMP:
			strcpy(protocol,"ICMP");
			break;
		case PROT_ANY:
			strcpy(protocol,"any");
			break;
		case PROT_OTHER:
			strcpy(protocol,"other");
			break;
		default:
			return scnprintf(buf,5,"%s","ERROR");

	}

	switch(rule->src_port){
		case PORT_ABOVE_1023:
			strcpy(src_port,">1023");
			break;
		case PORT_ANY:
			strcpy(src_port,"any");
			break;
		default:
			snprintf(src_port,4,"%d",rule->src_port);
			break;
	}

	switch(rule->dst_port){
		case PORT_ABOVE_1023:
			strcpy(dst_port,">1023");
			break;
		case PORT_ANY:
			strcpy(dst_port,"any");
			break;
		default:
			snprintf(dst_port,4,"%d",rule->dst_port);
			break;
	}

	switch(rule->ack){
		case ACK_YES:
			strcpy(ack,"yes");
			break;
		case ACK_NO:
			strcpy(ack,"no");
			break;
		case ACK_ANY:
			strcpy(ack,"any");
			break;
		default:
			return scnprintf(buf,5,"%s","ERROR");
	}

	switch(rule->action){
		case NF_ACCEPT:
			strcpy(action,"accept");
			break;
		case NF_DROP:
			strcpy(action,"drop");
			break;
		default:
			return scnprintf(buf,5,"%s","ERROR");
	}

	src_ip = kmalloc(19,GFP_ATOMIC);
	dst_ip = kmalloc(19,GFP_ATOMIC);

	if(!src_ip || !dst_ip){
		return scnprintf(buf,5,"%s","ERROR");
	}

	if(rule->src_prefix_size == 0){
		strcpy(src_ip,"any");
	}
	else{
		if(ip_to_string(rule->src_ip,src_ip) == ERROR){
			kfree(src_ip);
			kfree(dst_ip);
			return scnprintf(buf,5,"%s","ERROR");
		}
		snprintf(src_mask,3,"/%d",rule->src_prefix_size);
		strcat(src_ip,src_mask);
	}

	if(rule->dst_prefix_size == 0){
		strcpy(dst_ip,"any");
	}
	else{
		if(ip_to_string(rule->dst_ip,dst_ip) == ERROR){
			kfree(src_ip);
			kfree(dst_ip);
			return scnprintf(buf,5,"%s","ERROR");
		}
		snprintf(dst_mask,3,"/%d",rule->dst_prefix_size);
		strcat(dst_ip,dst_mask);
	}

	snprintf(rule_string,MAX_RULE_STRING_SIZE,"%s %s %s %s %s %s %s %s %s",rule->rule_name,direction,src_ip,dst_ip,protocol,src_port,dst_port,ack,action);

	kfree(src_ip);
	kfree(dst_ip);

	return scnprintf(buf, MAX_RULE_STRING_SIZE, " %s",rule_string);
}


decision_t* inspect_pkt(struct sk_buff *skb,direction_t dir){
	decision_t* res;
	struct iphdr* iph;
	struct tcphdr* tcph;
	conn_t* conn = NULL;
	conn_t* rev_conn = NULL;
	conn_t* lookup_conn = NULL;
	conn_t* lookup_rev_conn = NULL;
	int rule_num = REASON_ILLEGAL_VALUE;

	res = kmalloc(sizeof(decision_t),GFP_ATOMIC);
	if(!res){
		return NULL;
	}

	if(!is_active){
		res->action = NF_DROP;
		res->reason = REASON_FW_INACTIVE;
	 	return res;
	}

	iph = (struct iphdr*)skb_network_header(skb); //construct ip header of hooked pkt
	if(!iph){
		printk(KERN_INFO "failed at iph\n");
		res->action = NF_DROP;
		res->reason = REASON_ILLEGAL_VALUE;
	 	return res;
	}

	if(iph->protocol == PROT_TCP){
		tcph = (struct tcphdr*)((char*)iph + (iph->ihl * 4)); //https://stackoverflow.com/questions/10162556/why-skb-transport-header-does-not-calculate-correctly
		if(!tcph){
			printk(KERN_INFO "failed at tcph\n");
			res->action = NF_DROP;
			res->reason = REASON_ILLEGAL_VALUE;
			return res;
		}
		if(is_xmas(tcph)){
			res->action = NF_DROP;
			res->reason = REASON_XMAS_PACKET;
			return res;
		}
		conn = init_conn(ntohl(iph->saddr),ntohs(tcph->source),ntohl(iph->daddr),ntohs(tcph->dest));
		if(!conn){
			printk(KERN_INFO "failed at init_conn\n");
			res->action = NF_DROP;
			res->reason = REASON_ILLEGAL_VALUE;
			return res;		
		}

		printk(KERN_INFO "TCP flags:\n syn:%d fin:%d ack:%d psh:%d rst:%d urg:%d",tcph->syn,tcph->fin,tcph->ack,tcph->psh,tcph->rst,tcph->urg);

		if(!tcph->syn){
			printk(KERN_INFO "TCP doesn't have syn\n");
			if(compute_state(conn,tcph) == ERROR){
				printk(KERN_INFO "failed at compute state\n");
				kfree(conn);
				res->action = NF_DROP;
				res->reason = REASON_ILLEGAL_VALUE;
				return res;
			}

			//rev_conn = kmalloc(sizeof(conn_t),GFP_ATOMIC);
			rev_conn = reverse_conn(conn);
			if(!rev_conn){
				printk(KERN_INFO "failed at rev_conn\n");
				kfree(conn);
				res->action = NF_DROP;
				res->reason = REASON_ILLEGAL_VALUE;
				return res;
			}

			lookup_conn = lookup(conn,compare_conn);
			lookup_rev_conn = lookup(rev_conn,compare_conn);
			if(lookup_rev_conn == NULL){
				printk("lookup_rev_conn is null");
			}
			if(lookup_conn == NULL){
				printk("lookup_conn is null");
			}
			kfree(rev_conn);

			if(lookup_conn==NULL || lookup_rev_conn==NULL){ //conn or reverse conn not found
				printk(KERN_INFO "failed at lookup\n");
				kfree(conn);
				res->action = NF_DROP;
				res->reason = REASON_INVALID_CONNECTION;
				return res;
			}

			if(update_table(conn,lookup_conn,lookup_rev_conn) == ERROR){ //this also checks if state is valid
				printk(KERN_INFO "failed at update_table\n");
				kfree(conn);
				res->action = NF_DROP;
				res->reason = REASON_ILLEGAL_VALUE;
				return res;
			}

			kfree(conn);

			res->action = NF_ACCEPT;
			res->reason = REASON_VALID_CONNECTION;
			return res;
		}

		else{ //syn bit on
			printk(KERN_INFO "tcp has syn");
			if(tcph->ack){ //syn + ack
				//rev_conn = kmalloc(sizeof(conn_t),GFP_ATOMIC);
				rev_conn = reverse_conn(conn);
				if(!rev_conn){
					printk(KERN_INFO "failed at rev_conn 2\n");
					kfree(conn);
					res->action = NF_DROP;
					res->reason = REASON_ILLEGAL_VALUE;
					return res;
				}

				lookup_rev_conn = lookup(rev_conn,compare_conn);
				kfree(rev_conn);

				if(!lookup_rev_conn){ //reverse connection not found, meaning this is syn+ack sent before syn - drop
					printk(KERN_INFO "lookup_rev_conn not found\n");
					kfree(conn);
					res->action = NF_DROP;
					res->reason = REASON_INVALID_CONNECTION;
					return res;
				}

				if(lookup_rev_conn -> state != TCP_HANDSHAKE_SYN){ //reverse connection found, but it is past the beginning of three-way handshake
					printk(KERN_INFO "state is not handshake\n");
					kfree(conn);
					res->action = NF_DROP;
					res->reason = REASON_INVALID_CONNECTION;
					return res;	
				}


				if(assign_state(conn,TCP_HANDSHAKE_SYN_ACK) == ERROR){
					printk(KERN_INFO "failed at assign_state/add_connection\n");
					kfree(conn);
					res->action = NF_DROP;
					res->reason = REASON_ILLEGAL_VALUE;
					return res;	
				}

				if(add_connection(conn) == ERROR){
					printk(KERN_INFO "failed at add_conncetion\n");
					kfree(conn);
					res->action = NF_DROP;
					res->reason = REASON_ILLEGAL_VALUE;
					return res;
				}

				res->action = NF_ACCEPT;
				res->reason = REASON_VALID_CONNECTION;
				return res;
			}

			else{

				rule_num = compare_pkt_against_rules(skb,dir); //will be reached only if syn is on

				if(rule_num < 0){ //no matching rule
					kfree(conn);
					res->action = NF_DROP;
					res->reason = rule_num;
					return res;
				}

				if(rule_num > num_rules || rules[rule_num] == NULL){
					printk(KERN_INFO "Error!");
					kfree(conn);
					res->action = NF_DROP;
					res->reason = rule_num;
					return res;
				}

				if(rules[rule_num]->action == NF_DROP){ //packet not allowed by rule
					kfree(conn);
					res->action = NF_DROP;
					res->reason = rule_num;
					return res;
				}

				else if(assign_state(conn,TCP_HANDSHAKE_SYN) == ERROR || add_connection(conn) == ERROR){ //syn without ack
					printk(KERN_INFO "failed at assign_state/add_connection 2\n");
					kfree(conn);
					res->action = NF_DROP;
					res->reason = REASON_ILLEGAL_VALUE;
					return res;
				}

				res->action = NF_ACCEPT;
				res->reason = rule_num;
			}
		}

		return res;
	}

	else{ //not tcp
		rule_num = compare_pkt_against_rules(skb,dir); //will be reached only if syn is on

		if(rule_num < 0){ //no matching rule
			res->action = NF_DROP;
			res->reason = rule_num;
			return res;
		}

		res->action = rules[rule_num]->action;
		res->reason = rule_num;
		return res;
	}
	return NULL;
}