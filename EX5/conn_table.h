#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "conn.h"
#include "fw.h"
#include "fw_log.h"
#include "sha1.h"

#define SHA1_LENGTH 21

#define TABLE_SIZE 50

conn_t* lookup(conn_t* conn,int (*compare_func)(conn_t*,conn_t*));

int remove_conn_from_table(conn_t* conn,int (*compare_func)(conn_t*,conn_t*));

int update_table(conn_t* new,conn_t* conn_in_table,conn_t* rev);

int add_connection(conn_t* conn);

ssize_t show_conn(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t set_conn(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

ssize_t show_conn_tab_size(struct device *dev, struct device_attribute *attr, char *buf);

int compute_idx(conn_t* conn);

#endif