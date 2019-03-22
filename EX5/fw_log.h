#ifndef FW_LOG_H
#define FW_LOG_H
#include "fw.h"
#include "list.h"

node_t* add_log(log_row_t* log);
int compare_logs(log_row_t* a,log_row_t* b);
//int compare_nodes(node_t* a,node_t* b);
node_t* find_log(log_row_t* log);
int remove_log(log_row_t* log);
int log_pkt(log_row_t* log);
void clear_logs(void);
ssize_t num_logs_show(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t clear_logs_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
//ssize_t store_log(struct device *dev, struct device_attribute *attr, const char* buf,size_t count);
int snprintf(char *buf, size_t size, const char *fmt, ...);
int ip_to_string(unsigned int ip,unsigned char* s);
int show_logs(struct file* file,char __user* buffer,size_t length,loff_t* offset);
int device_open(struct inode* inode,struct file* file);
int device_release(struct inode* inode,struct file* file);
node_t* find_node_by_log(node_t* start,log_row_t* log,int (*compare_func)(log_row_t*,log_row_t*));

#endif