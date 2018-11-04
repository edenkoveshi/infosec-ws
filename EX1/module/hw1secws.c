#include <linux/module.h>
#include <linux/kernel.h>
#include  <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>

#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#define MODULE_NAME "pkt-sniffer"
#define SUCCESS 1
#define ERROR 0
#define HOST_1_IP 0x0a000101 //10.0.1.1
#define HOST_2_IP 0x0a000202 //10.0.2.2
#define FW_LEG_1 0x0a000103 //10.0.1.3
#define FW_LEG_2 0x0a000203 //10.0.2.3


MODULE_LICENSE("GPL");


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
		printk(KERN_ALERT "*** packet blocked ***");
		return NF_DROP;
	}

	if(!in){
		printk(KERN_ALERT "Error in 'in',exiting..");
		return NF_DROP;
	}

	if(!okfn){
		printk(KERN_ALERT "Error in okfn,exiting..");
		return NF_DROP;
	}

	//construcing ip header, and extracting destination ip
	iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL); //construct ip header of hooked pkt
	if(!iph){
		printk(KERN_ALERT "Error constructing IP packet\n");
		printk(KERN_ALERT "*** packet blocked ***");
		return NF_DROP;
	}

	dst_ip = be32_to_cpu(iph->daddr);

	/*
		Packets destined for FW
	*/
	if(dst_ip == FW_LEG_1 || dst_ip == FW_LEG_2){
		printk(KERN_INFO "*** packet passed ***");
		return NF_ACCEPT;
	}

	printk(KERN_ALERT "*** packet blocked ***");
	return NF_DROP;
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
		printk(KERN_ALERT "*** packet blocked ***");
		return NF_DROP;
	}

	if(!in){
		printk(KERN_ALERT "Error in 'in',exiting..");
		printk(KERN_ALERT "*** packet blocked ***");
		return NF_DROP;
	}

	if(!okfn){
		printk(KERN_ALERT "Error in okfn,exiting..");
		printk(KERN_ALERT "*** packet blocked ***");
		return NF_DROP;
	}

	//construcing ip header, and extracting destination ip
	iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL); //construct ip header of hooked pkt
	if(!iph){
		printk(KERN_ALERT "Error constructing IP packet\n");
		printk(KERN_ALERT "*** packet blocked ***");
		return NF_DROP;
	}

	src_ip = be32_to_cpu(iph->saddr);

	/*
		Packets coming from FW
	*/
	if(src_ip == FW_LEG_1 || src_ip == FW_LEG_2){
		printk(KERN_INFO "*** packet passed ***");
		return NF_ACCEPT;
	}

	printk(KERN_ALERT "*** packet blocked ***");
	return NF_DROP;
}



//init and exit functions
static int __init sniffer_init(void){
	printk(KERN_INFO "Loading module %s\n",MODULE_NAME);
	return nf_register_hook(&incoming_pkt_ops) && nf_register_hook(&outgoing_pkt_ops); //register both hooks
}

static void __exit sniffer_exit(void){
	nf_unregister_hook(&incoming_pkt_ops); //unregister hooks
	nf_unregister_hook(&outgoing_pkt_ops);
    printk(KERN_INFO "%s module stopped\n",MODULE_NAME);
}

module_init(sniffer_init);
module_exit(sniffer_exit);


