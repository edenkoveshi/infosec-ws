#include <linux/module.h>
#include <linux/kernel.h>
#include  <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/device.h>
#include <linux/fs.h>

#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#define MAJOR_NUM 42
#define MODULE_NAME "pkt-sniffer"
#define CLASS_NAME "sniffer"
#define SUCCESS 1
#define ERROR 0
#define HOST_1_IP 0x0a000101 //10.0.1.1
#define HOST_2_IP 0x0a000202 //10.0.2.2
#define FW_LEG_1 0x0a000103 //10.0.1.3
#define FW_LEG_2 0x0a000203 //10.0.2.3


MODULE_LICENSE("GPL");

static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

static unsigned int passed_ctr;
static unsigned int blocked_ctr;

//code partially taken from https://stackoverflow.com/questions/13071054/how-to-echo-a-packet-in-kernel-space-using-netfilter-hooks
static unsigned int inspect_incoming_pkt(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *));

static unsigned int inspect_outgoing_pkt(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *));

static struct nf_hook_ops incoming_pkt_ops = {
    .pf = NFPROTO_IPV4,
    .priority = 1,
    .hooknum = NF_INET_PRE_ROUTING,
    .hook = inspect_incoming_pkt,
};

static struct nf_hook_ops outgoing_pkt_ops = {
    .pf = NFPROTO_IPV4,
    .priority = 1,
    .hooknum = NF_INET_LOCAL_OUT,
    .hook = inspect_outgoing_pkt,
};

unsigned int Pass(void){
	passed_ctr++;
	printk(KERN_INFO "*** packet passed ***");
	return NF_ACCEPT;
}

unsigned int Block(void){
	blocked_ctr++;
	printk(KERN_INFO "*** packet blocked ***");
	return NF_DROP;
}


/*
	Upon catching an incoming packet, pass it forward iff it's destination ip belong to the FW.
*/
static unsigned int inspect_incoming_pkt(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *)){
	//variable declerations
	struct iphdr* iph;
	__u32 dst_ip;

	//error checks
	if(!skb){
		printk(KERN_ALERT "Error in skb,exiting..");
		return Block();
	}

	if(!in){
		printk(KERN_ALERT "Error in 'in',exiting..");
		return Block();
	}

	if(!okfn){
		printk(KERN_ALERT "Error in okfn,exiting..");
		return Block();
	}

	//construcing ip header, and extracting destination ip
	iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL); //construct ip header of hooked pkt
	if(!iph){
		printk(KERN_ALERT "Error constructing IP packet\n");
		return Block();
	}

	dst_ip = be32_to_cpu(iph->daddr);

	/*
		Packets destined for FW
	*/
	if(dst_ip == FW_LEG_1 || dst_ip == FW_LEG_2) return Pass();

	return Block();
}

/*
	Upon catching an outgoing packet, pass it forward iff it's source ip belong to the FWT
*/
static unsigned int inspect_outgoing_pkt(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *)){
	//variable declerations
	struct iphdr* iph;
	__u32 src_ip;

	//error checks
	if(!skb){
		printk(KERN_ALERT "Error in skb,exiting..");
		return Block();
	}

	if(!in){
		printk(KERN_ALERT "Error in 'in',exiting..");
		return Block();
	}

	if(!okfn){
		printk(KERN_ALERT "Error in okfn,exiting..");
		return Block();
	}

	//construcing ip header, and extracting destination ip
	iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL); //construct ip header of hooked pkt
	if(!iph){
		printk(KERN_ALERT "Error constructing IP packet\n");
		return Block();
	}

	src_ip = be32_to_cpu(iph->saddr);

	/*
		Packets coming from FW
	*/
	if(src_ip == FW_LEG_1 || src_ip == FW_LEG_2) return Pass();

	return Block();
}


ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%s\n%s : %d\n%s : %d\n%s : %d\n","Firewall Packets Summary:","Number of accepted packets",\
		passed_ctr,"Number of dropped packets",blocked_ctr,"Total number of packets",passed_ctr + blocked_ctr);
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1)
	{
		if(temp == 0){
			passed_ctr = 0;
			blocked_ctr = 0;
		}
	}
	return count;	
}

static DEVICE_ATTR(pkt_summary, S_IRWXO , display, modify);
//static DEVICE_ATTR(device_write, S_IRWXO, 0 , modify);


//init and exit functions
static int __init sniffer_init(void){
	int success;

	printk(KERN_INFO "Loading module %s\n",MODULE_NAME);

	passed_ctr = 0;
	blocked_ctr = 0;

	success = register_chrdev(MAJOR_NUM, MODULE_NAME, &fops);
	
	if (success < 0)
		return -1;
		
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(MAJOR_NUM, 0), NULL, MODULE_NAME);	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_pkt_summary.attr))
	{
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}
	return nf_register_hook(&incoming_pkt_ops) && nf_register_hook(&outgoing_pkt_ops); //register both hooks
}

static void __exit sniffer_exit(void){
	nf_unregister_hook(&incoming_pkt_ops); //unregister hooks
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_pkt_summary.attr);
	device_destroy(sysfs_class, MKDEV(MAJOR_NUM, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(MAJOR_NUM, MODULE_NAME);
	printk(KERN_INFO "%s module removed successfully",MODULE_NAME);
}

module_init(sniffer_init);
module_exit(sniffer_exit);


