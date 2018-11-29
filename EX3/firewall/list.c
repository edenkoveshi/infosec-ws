#include "list.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eden Koveshi");

node_t* init_node(void){
	node_t* node;
	node = kmalloc(sizeof(node_t),GFP_ATOMIC);
	if(node == NULL) return NULL;
	node->next = NULL;
	node->prev = NULL;
	node->log = NULL;
	return node;
}

int assign_log(node_t* node,log_row_t* log){
	if(log == NULL) return ERROR;
	if(node == NULL) return ERROR;
	node->log = log;
	return SUCCESS;
}

void destroy_node(node_t* node){
	if(node->log != NULL) kfree(node->log);
	kfree(node);
}

void remove_node(node_t* node){
	node_t* p = node->prev;
	node_t* n = node->next;
	destroy_node(node);
	p->next = n;
	n->prev = p;
}

int add_after(node_t* new,node_t* node){
	if(node == NULL){
		printk(KERN_INFO "node is null");
		return ERROR;
	}
	if(new == NULL){
		printk(KERN_INFO "new is null");
		return ERROR;
	}
	node->next = new;
	new->prev = node;
	return SUCCESS;
}

node_t* copy_node(node_t* node){
	node_t* copy = init_node();
	if(copy == NULL) return NULL;
	copy->next = node->next;
	copy->prev = node->prev;
	if(assign_log(copy,node->log) == ERROR){
		destroy_node(copy);
		return NULL;
	}
	return copy;
}

node_t* find_node(node_t* head,node_t* query, int (*compare_func)(node_t*,node_t*)){
	node_t* node = head;
	while(node != NULL && node->log != NULL){
		if(compare_func(node,query) == 0) return node;
		node = node->next;
	}
	return NULL;
}