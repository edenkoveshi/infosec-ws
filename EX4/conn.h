#ifndef CONN_H
#define CONN_H

#include "fw.h"

typedef enum{
	TCP_HANDSHAKE_SYN 		= 1, //syn sent
	TCP_HANDSHAKE_SYN_ACK	= 2, //syn ack sent
	TCP_CONN_ESTABLISHED 	= 4, //final ack sent, connection established
	TCP_ACK 				= 8,
	TCP_FIN 				= 16,//fin sent, can't send any more datagrams, but can recieve
	//TCP_FIN_RECIEVED = 16,//fin recieved, can still send data but no longer recieve data on this connection
} state_t;

typedef struct {
	__be32	src_ip;
	__be16 	src_port;
	__be32 	dst_ip;
	__be16 	dst_port;
	state_t state;
	unsigned long timeout; //0 - no timeout, not sure how good this is but timeout was not defined in case other than tcp handshake
	//this will be time of creation first, and timeout only if a new rule is inserted
} conn_t;

typedef struct conn_list_t {
	conn_t* conn;
	struct conn_list_t* next;
	//struct conn_list_t* prev;
} conn_list_t;

int compare_conn(conn_t* a,conn_t* b);

conn_t* init_conn(__be32 src_ip,__be16 src_port,__be32 dst_ip,__be16 dst_port);

conn_list_t* init_conn_node(conn_t* conn);

void destroy_conn_node(conn_list_t* list);

int add_after_conn_node(conn_list_t* list,conn_t* new);

conn_t* reverse_conn(conn_t* conn);

int compute_state(conn_t* conn,struct tcphdr* tcph);

int assign_state(conn_t* conn,state_t state);

int is_valid_state(state_t cur,state_t cur_in_table,state_t rev);

#endif