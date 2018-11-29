#include "fw.h"
#include "list.h"
#include "fw_log.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eden Koveshi");

static node_t* head;
static node_t* tail;
static unsigned long num_logs;
static DEFINE_SPINLOCK(xxx_lock);


node_t* add_log(log_row_t* log){
	node_t* node = init_node();
	if(node == NULL){
		printk(KERN_INFO "node is null");
		return NULL;
	}
	if(assign_log(node,log) == ERROR){
		printk(KERN_INFO "Error in assign_log, node destroyed");
		destroy_node(node);
		return NULL;
	}
	if(num_logs == 0){ 
		head = node;	
	}
	else{
		if(add_after(node,tail) == ERROR){
			printk(KERN_INFO "Error in add_after, node destroyed");
			destroy_node(node);
			return NULL;
		}
	}
	tail = node;
	num_logs++;
	log->count = 1;
	return node;
}

int compare_logs(log_row_t* a,log_row_t* b){
	if(a == NULL || b == NULL) return ERROR;
	if(a->protocol != b->protocol) return ERROR;
	if(a->action != b->action) return ERROR;
	if(a->hooknum != b->hooknum) return ERROR;
	if(a->src_ip != b->src_ip) return ERROR;
	if(a->dst_ip != b->dst_ip) return ERROR;
	if(a->src_port != b->src_port) return ERROR;
	if(a->dst_port != b->dst_port) return ERROR;
	if(a->reason != b->reason) return ERROR;
	return SUCCESS;
}

/*int compare_nodes(node_t* a,node_t* b){
	if(a->log == NULL || b->log == NULL) return ERROR;
	return compare_logs(a->log,b->log);
}*/

node_t* find_node_by_log(node_t* start,log_row_t* log,int (*compare_func)(log_row_t*,log_row_t*)){
	node_t* node = start;
	if(!log) return NULL;
	if(!start) return NULL;
	if(!compare_func) return NULL;
	while(node != NULL){
		if(node->log!=NULL){
			if(compare_func(node->log,log) == 0) return node;
		}
		node = node->next;
	}
	return NULL;
}

node_t* find_log(log_row_t* log){
	node_t* res;
	res = find_node_by_log(head,log,compare_logs);
	return res;
}

int remove_log(log_row_t* log){
	node_t* node;
	if(log == NULL) return ERROR;
	node = find_log(log);
	if(node == NULL) return ERROR;
	remove_node(node);
	num_logs--;
	return SUCCESS;
}

int log_pkt(log_row_t* log){
	node_t* node;
	unsigned long flags;

	if(log == NULL) return ERROR;

	spin_lock_irqsave(&xxx_lock, flags);
	node = find_log(log);

	if(node == NULL){
		node = add_log(log);
		if(node == NULL) return ERROR;
	}
	else{
		node->log->count++;
		printk(KERN_INFO "Node found");
	}

	node->log->timestamp = log->timestamp;
	printk(KERN_INFO "Logged!");
	spin_unlock_irqrestore(&xxx_lock, flags);
	return SUCCESS;
}

void clear_logs(void){
	node_t* t;
	int i=0;
	while(head!=NULL){
		printk(KERN_INFO "clearing node %d",i);
		t = head;
		head = head->next;
		destroy_node(t);
		i++;
	}
	num_logs = 0;
}

ssize_t num_logs_show(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%lu",num_logs);
}

ssize_t clear_logs_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	char temp;

	if (sscanf(buf, "%c", &temp) == 1)
	{
		clear_logs();
	}

	return count;
}

/*ssize_t store_log(struct device *dev, struct device_attribute *attr, const char* buf,size_t count){
	unsigned int temp;

	if (sscanf(buf, "%u", &temp) == 1)
	{
		if(temp == 1){
			log_pkt(new_log);
		}
	}

	return count;
}*/

int snprintf(char *buf, size_t size, const char *fmt, ...) //taken from: https://stackoverflow.com/questions/12264291/is-there-a-c-function-like-sprintf-in-the-linux-kernel
{
    va_list args;
    int i;

    va_start(args, fmt);
    i = vsnprintf(buf, size, fmt, args);
    va_end(args);

    return i;
}

int ip_to_string(unsigned int ip,unsigned char* s){ //from: https://stackoverflow.com/questions/1680365/integer-to-ip-address-c
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    return snprintf(s,15,"%d.%d.%d.%d",bytes[3],bytes[2],bytes[1],bytes[0]);
}

int show_logs(struct file* file,char __user* buffer,size_t length,loff_t* offset){
	char* s;
	char* final;
	unsigned long i = 0;
	node_t* node = head;
	log_row_t* log;
	char* src_ip;
	char* dst_ip;
	char protocol[5] = {0};
	char timestamp[19] = {0}; //length of "DD/MM/YYYY hh:mm:ss"
	struct rtc_time time;
	unsigned long local_time;
	char action[6] = {0};
	int log_size = 6*10+15*2+6+strlen("DD/MM/YYYY hh:mm:ss") + 10;

	if(num_logs == 0){
		i=0;
		while(i<length)
		{
			put_user(0,&buffer[i]);
			i++;
		}
		return 0;	
	}

	final = kmalloc(num_logs *log_size,GFP_ATOMIC);

	while(node!=NULL){

		if(node->log == NULL){
			kfree(final);
			i=0;
			while(i<length)
			{
				put_user(0,&buffer[i]);
				i++;
			}
			return ERROR; 
		}

		log = node->log;

		switch(log->protocol){
			case PROT_TCP:
				strncpy(protocol,"tcp",5);
				break;
			case PROT_UDP:
				strncpy(protocol,"udp",5);
				break;
			case PROT_ICMP:
				strncpy(protocol,"icmp",5);
				break;
			default:
				strncpy(protocol,"other",5);
				break;
		}

		local_time = (u32)(log->timestamp - (sys_tz.tz_minuteswest * 60));
		rtc_time_to_tm(local_time, &time);
		if(snprintf(timestamp,strlen("DD/MM/YYYY hh:mm:ss"),"%02d/%02d/%04d %02d:%02d:%02d",time.tm_mday,time.tm_mon + 1,1900 + time.tm_year,
			time.tm_hour,time.tm_min,time.tm_sec) == -1){
			kfree(final);
			i=0;
			while(i<length)
			{
				put_user(0,&buffer[i]);
				i++;
			}
			return ERROR;
		}

		if(log->action == NF_DROP){
			strncpy(action,"drop",strlen("drop"));
		}
		else{
			strncpy(action,"accept",strlen("accept"));	
		}

		src_ip = kmalloc(15,GFP_ATOMIC);
		if(!src_ip){
			kfree(final);
			i=0;
			while(i<length)
			{
				put_user(0,&buffer[i]);
				i++;
			}
			return ERROR;
		}

		dst_ip = kmalloc(15,GFP_ATOMIC);
		if(!dst_ip){
			kfree(final);
			kfree(src_ip);
			i=0;
			while(i<length)
			{
				put_user(0,&buffer[i]);
				i++;
			}
			return ERROR;
		}

		if(ip_to_string(log->src_ip,src_ip) == ERROR || ip_to_string(log->dst_ip,dst_ip) == ERROR){
			kfree(final);
			kfree(src_ip);
			kfree(dst_ip);
			i=0;
			while(i<length)
			{
				put_user(0,&buffer[i]);
				i++;
			}
			return ERROR;
		}

		s = kmalloc(log_size,GFP_ATOMIC);//6*(max int length) + 2*(max ip length) + max prot length + max date length
		if(!s){
			kfree(final);
			kfree(src_ip);
			kfree(dst_ip);
			i=0;
			while(i<length)
			{
				put_user(0,&buffer[i]);
				i++;
			}
			return ERROR;
		}

		memset(s,0,log_size);

		if(snprintf(s,log_size,"%s %s %s %u %u %s %u %s %d %u\n",timestamp,src_ip,dst_ip,log->src_port,log->dst_port,
			protocol,log->hooknum,action,log->reason,log->count) == ERROR)
		{
			kfree(final);
			kfree(src_ip);
			kfree(dst_ip);
			kfree(s);
			i=0;
			while(i<length)
			{
				put_user(0,&buffer[i]);
				i++;
			}
			return ERROR;
		}

		if(!strcat(final,s)){
			kfree(final);
			kfree(src_ip);
			kfree(dst_ip);
			kfree(s);
			i=0;
			while(i<length)
			{
				put_user(0,&buffer[i]);
				i++;
			}
			return ERROR;
		}

		node = node->next;
	}

	while(i<length && i<strlen(final))
	{
		if(put_user(final[i],&buffer[i])!=0) //read. abort and return empty string if reading failed
		{
			kfree(final);
			i=0;
			while(i<length)
			{
				put_user(0,&buffer[i]);
				i++;
			}
			return ERROR;
		}

		i++;
	}

	kfree(final);
	return num_logs;	
}


int device_open(struct inode* inode,struct file* file)
{
	return SUCCESS;
}

int device_release(struct inode* inode,struct file* file)
{
	return SUCCESS;
}