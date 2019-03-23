#include "conn.h"


int compare_conn(conn_t* a,conn_t* b){
	if(a == NULL || b == NULL) return ERROR;
	//if(a->timeout != 0 && b->timeout > a->timeout) return ERROR; //as b is a new connection, timeout represents it's time of creation, which is the current time
	if(a->src_ip != b->src_ip) return ERROR;
	if(a->src_port != b->src_port) return ERROR;
	if(a->dst_ip != b->dst_ip) return ERROR;
	if(a->dst_port != b->dst_port) return ERROR;
	return SUCCESS;
}

conn_t* init_conn(__be32 src_ip,__be16 src_port,__be32 dst_ip,__be16 dst_port){
	conn_t* conn;
	conn = kmalloc(sizeof(conn_t),GFP_ATOMIC);
	if(!conn) return NULL;
	conn->src_ip = src_ip;
	conn->src_port = src_port;
	conn->dst_ip = dst_ip;
	conn->dst_port = dst_port;
	return conn;
}

conn_list_t* init_conn_node(conn_t* conn){
	conn_list_t* list;
	printk(KERN_INFO "in init_conn_node");
	if(!conn) return NULL;
	list = kmalloc(sizeof(conn_list_t),GFP_ATOMIC);
	if(!list) return NULL;
	list->next = NULL;
	list->conn = conn;
	printk(KERN_INFO "finished init_conn_node");
	return list;
}

void destroy_conn_node(conn_list_t* toRemove, conn_list_t* prev){
	/*if(list->conn != NULL) kfree(list->conn);
	kfree(list);*/
	if(toRemove != NULL){
		
		if(prev != NULL){
			if(toRemove->next != NULL){
				prev->next = toRemove->next;
			}
			else{
				prev->next = NULL;
			}
		}

		if(toRemove->conn != NULL) kfree(toRemove->conn);
		if(prev != NULL) kfree(toRemove); //make sure to not remove the initialized beginning node
	}
}

int add_after_conn_node(conn_list_t* list,conn_t* new){
	printk(KERN_INFO "in add_after_conn_node");
	if(!list) return ERROR;
	if(!new) return ERROR;
	list->next = init_conn_node(new);
	if(!list) return ERROR;
	if(!list->next) return ERROR;
	printk(KERN_INFO "finished add_after_conn_node");
	return SUCCESS;
}

conn_t* reverse_conn(conn_t* conn){
	conn_t* reverse;
	if(!conn) return NULL;
	reverse = kmalloc(sizeof(conn_t),GFP_ATOMIC);
	if(!reverse) return NULL;
	reverse->src_ip = conn->dst_ip;
	reverse->src_port = conn->dst_port;
	reverse->dst_ip = conn->src_ip;
	reverse->dst_port = conn->src_port;
	//reverse->timeout = conn->timeout;
	return reverse;
}

int compute_state(conn_t* conn,struct tcphdr* tcph){
	if(!conn){
		printk(KERN_INFO "conn is null");
		return ERROR;
	}

	if(!tcph){
		printk(KERN_INFO "tcph is null");
		return ERROR;
	}

	if(tcph->syn && !tcph->ack){
		conn->state = TCP_HANDSHAKE_SYN;
	}

	else if(tcph->syn && tcph->ack){
		conn->state = TCP_HANDSHAKE_SYN_ACK;
	}

	else if(tcph->fin){
		conn->state = TCP_FIN;
	}

	else if(tcph->ack){
		conn->state = TCP_ACK;
	}

	else{
		conn->state = TCP_CONN_ESTABLISHED;
	}

	return SUCCESS;
}

int assign_state(conn_t* conn,state_t state){
	if(conn == NULL) return ERROR;
	conn->state = state;
	return SUCCESS;
}

/*int assign_state_2(conn_t* conn,state_t state){
	if(!conn) return ERROR;
	conn->state = state;
	return SUCCESS;
}*/

int is_valid_state(state_t cur,state_t cur_in_table,state_t rev){
    switch(cur){
      case TCP_ACK:
      	if(cur_in_table == TCP_CONN_ESTABLISHED && rev == TCP_CONN_ESTABLISHED) return SUCCESS;
      	if(cur_in_table == TCP_HANDSHAKE_SYN && rev == TCP_HANDSHAKE_SYN_ACK) return SUCCESS;
      	if(cur_in_table == TCP_FIN && rev == TCP_FIN) return SUCCESS;
      	break;
      case TCP_FIN:
      	if(cur_in_table == TCP_FIN) return ERROR;
      	return SUCCESS;
      	break;
      default: //should not reach syn or syn ack
      	return ERROR;
      	break;
    }

    return ERROR;
}