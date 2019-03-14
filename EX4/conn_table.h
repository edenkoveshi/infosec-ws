#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "conn.h"
#include "fw.h"

#define TABLE_SIZE 50

unsigned int joaat_hash(unsigned char *key, size_t len);

void init_conn_table(void);

void clean_conn_table(void);

conn_t* lookup(conn_t* conn,int (*compare_func)(conn_t*,conn_t*));

void remove_conn_from_table(conn_t* conn,int (*compare_func)(conn_t*,conn_t*));

int update_table(conn_t* new,conn_t* conn_in_table,conn_t* rev);

int add_connection(conn_t* conn);



#endif