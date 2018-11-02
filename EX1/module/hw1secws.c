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

#define MAJOR_NUM 42
#define MODULE_NAME "pkt-sniffer"
#define SUCCESS 1
#define ERROR 0
#define HOST_1_IP 0x0a000101 //10.0.1.1
#define HOST_2_IP 0x0a000202 //10.0.2.2
#define FW_LEG_1 0x0a000103 //10.0.1.3
#define FW_LEG_2 0x0a000203 //10.0.2.3
#define FW_LEG_3 0x0a000403 //10.0.4.3


MODULE_LICENSE("GPL");


int contains(__u32 array[],__u32 item);
int length(__u32 array[]);
__u32 inline_network[] = {HOST_1_IP,HOST_2_IP,FW_LEG_1,FW_LEG_1};

//code partially taken from https://stackoverflow.com/questions/13071054/how-to-echo-a-packet-in-kernel-space-using-netfilter-hooks
static unsigned int inspect_incoming_pkt(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *));

/*static unsigned int inspect_outgoing_pkt(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *));*/

static struct nf_hook_ops incoming_pkt_ops = {
    .pf = NFPROTO_IPV4,
    .priority = 1,
    .hooknum = NF_INET_PRE_ROUTING,
    .hook = inspect_incoming_pkt,
};

/*static struct nf_hook_ops outgoing_pkt_ops = {
    .pf = NFPROTO_IPV4,
    .priority = 1,
    .hooknum = NF_INET_LOCAL_OUT,
    .hook = inspect_outgoing_pkt,
};*/

static unsigned int inspect_incoming_pkt(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *)){
	//variable declerations
	struct iphdr* iph;
	__u32 src_ip;
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

	/*if(!out){
		printk(KERN_ALERT "Error in out,exiting..");
		return NF_DROP;
	}*/

	if(!okfn){
		printk(KERN_ALERT "Error in okfn,exiting..");
		return NF_DROP;
	}


	iph = (struct iphdr *) skb_header_pointer (skb, 0, 0, NULL); //construct ip header of hooked pkt
	if(!iph){
		printk(KERN_ALERT "Error constructing IP packet\n");
		printk(KERN_ALERT "*** packet blocked ***");
		return NF_DROP;
	}

	src_ip = be32_to_cpu(iph->saddr);
	dst_ip = be32_to_cpu(iph->daddr);

	/*printk(KERN_INFO "src_ip:%u",src_ip);
	printk(KERN_INFO "LEG_1:%u",FW_LEG_1);
	printk(KERN_INFO "LEG_2:%u",FW_LEG_2);
	printk(KERN_INFO "dst_ip:%u",dst_ip);
	printk(KERN_INFO "HOST_1:%u",HOST_1_IP);
	printk(KERN_INFO "HOST_2:%u",HOST_2_IP);*/

	/*
		Packet from inside the inline network
	*/
	if(contains(inline_network,src_ip)){
		printk(KERN_INFO "*** packet passed ***");
		return NF_ACCEPT;
	}

	/*
		Packets destined for FW
	*/
	if(dst_ip == FW_LEG_1 || dst_ip == FW_LEG_2 || dst_ip == FW_LEG_3){
		printk(KERN_INFO "*** packet passed ***");
		return NF_ACCEPT;
	}

	/*
		Communication with rest of the internet
	*/
	if(src_ip == FW_LEG_3 || !contains(inline_network,dst_ip)){
		printk(KERN_INFO "*** packet passed ***");
		return NF_ACCEPT;
	}

	/*
		Packet coming from host 1 or host 2
	
	if((src_ip == HOST_1_IP || src_ip == HOST_2_IP)){
		printk(KERN_ALERT "*** packet passed ***");
		return NF_ACCEPT;
	}
	*/

	printk(KERN_ALERT "*** packet blocked ***");
	return NF_DROP;
}

/*static unsigned int inspect_outgoing_pkt(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *)){
	printk(KERN_ALERT "Outgoing packet recieved");
	return NF_ACCEPT;
}*/

/*
	Check whether __u32 array contains an item of type __u32
*/
int contains(__u32 array[],__u32 item){
	int i;
	for(i=0;i<length(array);i++){
		if(array[i] == item) return SUCCESS;
	}
	return ERROR;
}

/*
	Return length of a __u32 array
*/
int length(__u32 array[]){
	int i=0;
	while(array[i] != NULL){
		i++;
	}
	return i;
}



//init and exit functions
static int __init sniffer_init(void){
	printk(KERN_INFO "Loading module %s\n",MODULE_NAME);
	return nf_register_hook(&incoming_pkt_ops);// && nf_register_hook(&outgoing_pkt_ops);
}

static void __exit sniffer_exit(void){
	nf_unregister_hook(&incoming_pkt_ops);
	//nf_unregister_hook(&outgoing_pkt_ops);
    printk(KERN_INFO "%s module stopped\n",MODULE_NAME);
}

module_init(sniffer_init);
module_exit(sniffer_exit);


