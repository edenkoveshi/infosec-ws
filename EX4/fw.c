#include "fw.h"
#include "fw_log.h"
#include "fw_rules.h"
#include "conn.h"
#include "conn_table.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eden Koveshi");

static struct class* sysfs_class = NULL;	// The device's class
static struct device* rules_device = NULL;	// The device's name
static struct device* log_device = NULL;
static DEFINE_SPINLOCK(xxx_lock);

struct file_operations log_fops =
{
  .owner = THIS_MODULE,
  .read = show_logs,
  .open = device_open,
  .release = device_release,

};

static struct nf_hook_ops forwarded_pkt_ops = { //forwarding hook
    .pf = NFPROTO_IPV4,
    .priority = 1,
    .hooknum = NF_INET_PRE_ROUTING,
    .hook = hook_func,
};

static struct nf_hook_ops internal_outgoing_pkt_ops = { //output hook
    .pf = NFPROTO_IPV4,
    .priority = 1,
    .hooknum = NF_INET_LOCAL_OUT,
    .hook = hook_func_local_out,
};

static struct nf_hook_ops internal_incoming_pkt_ops = { //input hook
	.pf = NFPROTO_IPV4,
	.priority =1 ,
	.hooknum = NF_INET_LOCAL_IN,
	.hook = hook_func_local_in,
};

unsigned int hook_func(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *)){
	decision_t* result; //0 - action, 1 - reason
	int action;
	direction_t dir = DIRECTION_ANY;
	log_row_t* log;
	unsigned long flags;
	struct iphdr* iph;
	struct tcphdr* tcph;
	//int tcplen;

	spin_lock_irqsave(&xxx_lock, flags);	


	//error checks
	if(!skb){
		printk(KERN_ALERT "Error in skb,exiting..");
		result = kmalloc(sizeof(decision_t),GFP_ATOMIC);
		result->action = NF_DROP;
		result->reason = REASON_ILLEGAL_VALUE;
		log = create_log(skb,result,hooknum);
		log_pkt(log);
		kfree(result);
		return NF_DROP;
	}

	if(!in){
		printk(KERN_ALERT "Error in 'in',exiting..");
		result = kmalloc(sizeof(decision_t),GFP_ATOMIC);
		result->action = NF_DROP;
		result->reason = REASON_ILLEGAL_VALUE;
		log = create_log(skb,result,hooknum);
		log_pkt(log);
		kfree(result);
		return NF_DROP;
	}

	/*if(!out){
		printk(KERN_ALERT "Error in 'out',exiting..");
		result = kmalloc(sizeof(decision_t),GFP_ATOMIC);
		result->action = NF_DROP;
		result->reason = REASON_ILLEGAL_VALUE;
		log = create_log(skb,result,hooknum);
		log_pkt(log);
		kfree(result);
		return NF_DROP;	
	}*/

	if(!okfn){
		printk(KERN_ALERT "Error in okfn,exiting..");
		result = kmalloc(sizeof(decision_t),GFP_ATOMIC);
		result->action = NF_DROP;
		result->reason = REASON_ILLEGAL_VALUE;
		log = create_log(skb,result,hooknum);
		log_pkt(log);
		kfree(result);
		return NF_DROP;
	}

	dir = DIRECTION_ANY;
	if(strcmp(in->name,IN_NET_DEVICE_NAME) == 0) { dir = DIRECTION_IN; }
	else if(strcmp(in->name,OUT_NET_DEVICE_NAME) == 0) { dir = DIRECTION_OUT; }
	else{
		printk(KERN_ALERT "No matching direction\n");
		result = kmalloc(sizeof(decision_t),GFP_ATOMIC);
		result->action = NF_DROP;
		result->reason = REASON_ILLEGAL_VALUE;
		log = create_log(skb,result,hooknum);
		log_pkt(log);
		kfree(result);
		return NF_DROP;
	}
	
	result = inspect_pkt(skb,dir);
	if(!result) return NF_DROP;
	log = create_log(skb,result,(unsigned char)hooknum);
	if(log == NULL) return NF_DROP;
	if(!IS_LOCALHOST(log->src_ip) || !IS_LOCALHOST(log->dst_ip)){ //do not log localhost
		if(log_pkt(log) == ERROR){
			printk(KERN_ALERT "Packet logging failed");
			return NF_DROP;
		}
	}
	else{
		kfree(log);
	}

	printk(KERN_INFO "**** action: %u reason: %d ******",result->action,result->reason);

	action = result->action;
	if(action != NF_DROP && action != NF_ACCEPT) action = NF_DROP; //for safety
	kfree(result);

	if(action == NF_ACCEPT){//} && ((hooknum == NF_INET_PRE_ROUTING && dir = DIRECTION_IN) || (hooknum = NF_INET_LOCAL_OUT && dir = DIRECTION_OUT)){
		if(skb_network_header(skb) == NULL){
			printk(KERN_INFO "skb_network_header is null\n");
			return action;
		}
		iph = (struct iphdr*)(skb_network_header(skb)); //construct ip header of hooked pkt
		if(iph){
			//printk(KERN_INFO "HEREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\n");
			tcph = (struct tcphdr *)(skb_transport_header(skb)+20);
			if (tcph){
				redirect_in(skb);
			}
		}
	}

	spin_unlock_irqrestore(&xxx_lock, flags);

	return action;
	//return NF_ACCEPT;
}

void redirect_in(struct sk_buff* skb){
	int tcplen;
	int check = 0;
	struct iphdr *iph;
	struct tcphdr *tcph;

	if(!skb){
		printk(KERN_INFO "skb is null\n");
		return;	
	}

	if (skb_linearize(skb) != 0) {
		printk(KERN_INFO "skb linearize failed\n");
        return;
    }

    iph = ip_hdr(skb);

    if(!iph){
		printk(KERN_INFO "iph is null");
		return;
	}

    tcph = (void *)iph + (iph->ihl << 2);
    
	if(!tcph){
		printk(KERN_INFO "tcph is null");
		return;
	}

	printk(KERN_INFO "@@@@@@@@@@@@@starting redirect in@@@@@@@@@@@@");
	printk(KERN_INFO "src ip: %u, dst ip:%u, src port:%u, dst port: %u",ntohl(iph->saddr),ntohl(iph->daddr),ntohs(tcph->source),ntohs(tcph->dest));
	printk(KERN_INFO "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	
	if (tcph->dest == htons(80) && iph->daddr == htonl(HOST2_OUT_IP)) //client to HTTP server. redirect to local proxy
	{	
		iph->daddr = htonl(HOST1_IN_IP);   //10.0.1.3
		tcph->dest = htons(PROXY_HTTP_PORT); //proxy listening port
		check = 1;
	}
	if (tcph->source == htons(80) && iph->daddr == htonl(HOST1_OUT_IP)) //HTTP server to client. redirect to local proxy
	{	
		iph->daddr = htonl(HOST2_IN_IP);   //10.0.2.3
		check = 1;
	}
	
	if (tcph->dest == htons(21) && iph->daddr == htonl(HOST2_OUT_IP)) //client to FTP server. redirect to local proxy
	{	
		iph->daddr = htonl(HOST1_IN_IP);   //10.0.1.3
		tcph->dest = htons(PROXY_FTP_PORT); //proxy listening port
		check = 1;
	}
	if (tcph->source == htons(21) && iph->daddr == htonl(HOST1_OUT_IP)) //FTP server to client. redirect to local proxy
	{	
		iph->daddr = htonl(HOST2_IN_IP);   //10.0.2.3
		check = 1;
	}

	if (tcph->source == htons(20) && iph->saddr == htonl(HOST2_OUT_IP)) //FTP-DATA server to client. redirect to local proxy
	{	
		iph->daddr = htonl(HOST2_IN_IP);   //10.0.2.3
		check = 1;
	}
	if (tcph->dest == htons(20) && iph->saddr == htonl(HOST1_OUT_IP)) //FTP-DATA client to server. redirect to local proxy
	{	
		iph->daddr = htonl(HOST1_IN_IP);   //10.0.1.3
		check = 1;
	}

	/*if(ip_hdrlen(skb) == NULL){
		printk(KERN_INFO "ip_hdrlen is null\n");
		return;
	}*/
	if(check){
		tcplen = skb->len - ip_hdrlen(skb);
	    tcph->check=0;
	    /*if(csum_partial((char*)tcph,tcplen,0) == NULL){
	    	printk(KERN_INFO "csum_partial is null\n");
	    	return;
	    }*/

	    tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr,csum_partial((char*)tcph, tcplen,0));
	    skb->ip_summed = CHECKSUM_NONE;
	    iph->check = 0;
	    /*if(ip_fast_csum((u8 *)iph, iph->ihl) == NULL){
	    	printk(KERN_INFO "fast csum failed\n");
	    	return;
	    }*/

	    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
	    

    	printk(KERN_INFO "@@@@@@@@@@@@@ending redirect in@@@@@@@@@@@@@@");
		printk(KERN_INFO "src ip: %u, dst ip:%u, src port:%u, dst port: %u",ntohl(iph->saddr),ntohl(iph->daddr),ntohs(tcph->source),ntohs(tcph->dest));
		printk(KERN_INFO "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	}
	return;
}

void redirect_out(struct sk_buff *skb){
	//https://stackoverflow.com/questions/16610989/calculating-tcp-checksum-in-a-netfilter-module
	int tcplen;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int check = 0;

	if(!skb){
		printk(KERN_INFO "skb is null\n");
		return;	
	}

	if (skb_linearize(skb) != 0) {
		printk(KERN_INFO "skb linearize failed\n");
        return;
    }

    iph = ip_hdr(skb);

    if(!iph){
		printk(KERN_INFO "iph is null");
		return;
	}

    tcph = (void *)iph + (iph->ihl << 2);
    
	if(!tcph){
		printk(KERN_INFO "tcph is null");
		return;
	}
    

	printk(KERN_INFO "@@@@@@@@@@@@@starting redirect out@@@@@@@@@@@");
	printk(KERN_INFO "src ip: %u, dst ip:%u, src port:%u, dst port: %u",ntohl(iph->saddr),ntohl(iph->daddr),ntohs(tcph->source),ntohs(tcph->dest));
	printk(KERN_INFO "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");


	if (tcph->dest == htons(80) && iph->saddr == htonl(HOST2_IN_IP)) //local proxy to http server. change source ip to be that of the client.
	{			
		//change source ip
		iph->saddr = htonl(HOST1_OUT_IP);	  //10.0.1.1
		check = 1;
	}
	if (tcph->source == htons(PROXY_HTTP_PORT)) //local proxy to client. change source ip and port to be that of the server.
	{			
		//change source ip
		iph->saddr = htonl(HOST2_OUT_IP);	  //10.0.2.2
		tcph->source = htons(80);
		check = 1;
	}
	
	if (tcph->dest == htons(21) && iph->saddr == htonl(HOST2_IN_IP)) //local proxy to ftp server. change source ip to be that of the client.
	{			
		//change source ip
		iph->saddr = htonl(HOST1_OUT_IP);	  //10.0.1.1
		check = 1;
	}
	if (tcph->source == htons(PROXY_FTP_PORT)) //local proxy to client. change source ip and port to be that of the server.
	{			
		//change source ip
		iph->saddr = htonl(HOST2_OUT_IP);	  //10.0.2.2
		tcph->source = htons(21);
		check = 1;
	}
	
	if (tcph->dest == htons(20) && iph->saddr == htonl(HOST2_IN_IP)) //local proxy to FTP-DATA server. change source ip to be that of the client.
	{			
		//change source ip
		iph->saddr = htonl(HOST1_OUT_IP);	  //10.0.1.1
		check = 1;
	}
	if (tcph->source == htons(20) && iph->daddr == htonl(HOST1_OUT_IP)) //local proxy to FTP-DATA client. change source ip and port to be that of the server.
	{			
		//change source ip
		iph->saddr = htonl(HOST2_OUT_IP);	  //10.0.2.2
		check = 1;
	}
	
	//here starts the checksum fix for both IP and TCP
	if(check){
		tcplen = skb->len - ip_hdrlen(skb);
	    tcph->check=0;
	    /*if(csum_partial((char*)tcph,tcplen,0) == NULL){
	    	printk(KERN_INFO "csum_partial is null\n");
	    	return;
	    }*/

	    tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr,csum_partial((char*)tcph, tcplen,0));
	    skb->ip_summed = CHECKSUM_NONE;
	    iph->check = 0;
	    /*if(ip_fast_csum((u8 *)iph, iph->ihl) == NULL){
	    	printk(KERN_INFO "fast csum failed\n");
	    	return;
	    }*/

	    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
	    printk(KERN_INFO "@@@@@@@@@@@@@ending redirect out@@@@@@@@@@@@@");
		printk(KERN_INFO "src ip: %u, dst ip:%u, src port:%u, dst port: %u",ntohl(iph->saddr),ntohl(iph->daddr),ntohs(tcph->source),ntohs(tcph->dest));
		printk(KERN_INFO "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
	}
	return;
}


unsigned int hook_func_local_in(unsigned int hooknum, 
								struct sk_buff *skb, 
								const struct net_device *in, 
								const struct net_device *out, 
								int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	unsigned int sip,dip;
	if(skb != NULL){ //error check
		iph = (struct iphdr *)skb_network_header(skb);
		if(!iph){
			return NF_DROP;
		}
		sip   = ntohl(iph->saddr);
		dip   = ntohl(iph->daddr);
		printk(KERN_INFO "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		printk(KERN_INFO "Local In Packet: sip = %u.dip = %u",sip,dip);
		printk(KERN_INFO "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		if (IS_LOCALHOST(sip) && IS_LOCALHOST(dip)){
			return NF_ACCEPT;
		}
		if (dip == HOST1_IN_IP || dip == HOST2_IN_IP){ //proxy
			return NF_ACCEPT;
		}
	}
	printk(KERN_INFO "Dropping Local In Packet\n");
	return NF_DROP;
}

unsigned int hook_func_local_out(unsigned int hooknum, 
								struct sk_buff *skb, 
								const struct net_device *in, 
								const struct net_device *out, 
								int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph; 
	struct tcphdr *tcph;
	//unsigned short int sport, dport;
	int sip, dip;
	//decision_t* d;
	if(skb != NULL){ //error check

		iph = (struct iphdr *)skb_network_header(skb);
		if(!iph){ //not ip packet
			return NF_ACCEPT;
		}
		sip   = ntohl(iph->saddr);
		dip   = ntohl(iph->daddr);

		printk(KERN_INFO "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		printk(KERN_INFO "Local Out Packet: sip = %u.dip = %u",sip,dip);
		printk(KERN_INFO "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		
		if (IS_LOCALHOST(sip) && IS_LOCALHOST(dip)){
			return NF_ACCEPT;
		}
		if (dip == HOST1_OUT_IP || dip == HOST2_OUT_IP){ //proxy
			if (iph->protocol==IPPROTO_TCP){ //TCP
				//d = inspect_pkt(skb,DIRECTION_OUT);
				//redirect_out(skb);
				return NF_ACCEPT;
			}
		}
	}
	//skb is null or protocol is not ipv4
	printk(KERN_INFO "Dropping Local Out Packet\n");
	return NF_DROP;

}	

static DEVICE_ATTR(log_size, S_IROTH , num_logs_show, NULL);
static DEVICE_ATTR(log_clear, S_IWOTH , NULL , clear_logs_store);
//static DEVICE_ATTR(log_new_pkt, S_IWOTH, NULL, store_log);
static DEVICE_ATTR(active, S_IROTH|S_IWOTH , active_show, active_store);
static DEVICE_ATTR(rules_size, S_IROTH , size_show, NULL);
static DEVICE_ATTR(add_rule,S_IWOTH, NULL, rule_store);
static DEVICE_ATTR(clear_rules,S_IWOTH, NULL, clear_rules_store);
static DEVICE_ATTR(show_rules,S_IROTH | S_IWOTH,get_rule,set_cur_rule);

static char *log_devnode(struct device *dev, umode_t *mode) //https://stackoverflow.com/questions/11846594/how-can-i-programmatically-set-permissions-on-my-char-device
{
        if (!mode)
                return NULL;
        if (dev->devt == MKDEV(MAJOR_NUM, 1))
                *mode = 0666;
        return NULL;
}

static int __init fw_init(void){
	int major_num;
	printk(KERN_INFO "Loading firewall");
	major_num = register_chrdev(MAJOR_NUM, MODULE_NAME, &log_fops);
	
	if (major_num < 0) {
		return ERROR;
	}
	
	sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
	
	if (IS_ERR(sysfs_class)) {
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	sysfs_class->devnode = log_devnode;

	rules_device = device_create(sysfs_class, NULL, MKDEV(MAJOR_NUM, MINOR_RULES), NULL, CLASS_NAME "_" DEVICE_NAME_RULES);	

	if (IS_ERR(rules_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	log_device = device_create(sysfs_class, NULL, MKDEV(MAJOR_NUM, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);	

	if (IS_ERR(log_device)) {
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM,MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr))
	{
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_log_clear.attr))
	{
		device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_show_rules.attr))
	{
		device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
		device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	clear_rules();
	add_localhost();
	add_prot_other();
	init_conn_table();

	nf_register_hook(&forwarded_pkt_ops);
	nf_register_hook(&internal_incoming_pkt_ops);
	nf_register_hook(&internal_outgoing_pkt_ops);	

	return 0;
}

static void __exit fw_exit(void){
	nf_unregister_hook(&internal_outgoing_pkt_ops);
	nf_unregister_hook(&internal_incoming_pkt_ops);
	nf_unregister_hook(&forwarded_pkt_ops);
	clear_logs();
	clear_rules();
	clean_conn_table();
	device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
	device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_show_rules.attr);
	device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
	device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
	class_destroy(sysfs_class);
	unregister_chrdev(MAJOR_NUM, MODULE_NAME);
	printk(KERN_INFO "%s module removed successfully",DEVICE_NAME_LOG);
}

module_init(fw_init);
module_exit(fw_exit);