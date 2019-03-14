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

static struct nf_hook_ops incoming_pkt_ops = {
    .pf = NFPROTO_IPV4,
    .priority = 1,
    .hooknum = NF_INET_PRE_ROUTING,
    .hook = hook_func,
};

static struct nf_hook_ops outgoing_pkt_ops = {
    .pf = NFPROTO_IPV4,
    .priority = 1,
    .hooknum = NF_INET_LOCAL_OUT,
    .hook = hook_func,
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
	int tcplen;

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

	/*if(!in){
		printk(KERN_ALERT "Error in 'in',exiting..");
		result = kmalloc(sizeof(decision_t),GFP_ATOMIC);
		result->action = NF_DROP;
		result->reason = REASON_ILLEGAL_VALUE;
		log = create_log(skb,result,hooknum);
		log_pkt(log);
		kfree(result);
		return NF_DROP;
	}

	if(!out){
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

	/*if(strcmp(in->name,IN_NET_DEVICE_NAME) == 0) dir = DIRECTION_OUT;
	else if(strcmp(in->name,OUT_NET_DEVICE_NAME) == 0) dir = DIRECTION_IN;
	else{
		printk(KERN_ALERT "no matching direction. in->name = %s",in->name);
		result = kmalloc(sizeof(decision_t),GFP_ATOMIC);
		result->action = NF_DROP;
		result->reason = REASON_ILLEGAL_VALUE;
		log = create_log(skb,result,hooknum);
		log_pkt(log);
		kfree(result);
		return NF_DROP;
	}*/

	dir = DIRECTION_IN;
	
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
	kfree(result);

	/*if(action == NF_ACCEPT){
		iph = (struct iphdr*)skb_network_header(skb); //construct ip header of hooked pkt
		if(iph){
			tcph = (struct tcphdr*)((char*)iph + (iph->ihl * 4));
			if (tcph){
				if (tcph->dest == htons(80) || tcph->source == htons(80)) //HTTP
				{	
					//changing of routing
					iph->daddr = PROXY_IP; //change to yours IP
					//tcp_header->dest = <my_port>; //change to yours listening port
					
					//here start the fix of checksum for both IP and TCP
					tcplen = (skb->len - ((iph->ihl )<< 2));
			        tcph->check = 0;
			        tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr,csum_partial((char*)tcph, tcplen,0));
			        skb->ip_summed = CHECKSUM_NONE; //stop offloading
			        iph->check = 0;
			        iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
			    }
			}
		}
	}*/

	spin_unlock_irqrestore(&xxx_lock, flags);

	return action;
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

	nf_register_hook(&incoming_pkt_ops);
	nf_register_hook(&outgoing_pkt_ops);	

	return 0;
}

static void __exit fw_exit(void){
	nf_unregister_hook(&incoming_pkt_ops);
	nf_unregister_hook(&outgoing_pkt_ops);
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