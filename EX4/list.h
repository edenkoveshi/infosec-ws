#ifndef LIST_H
#define LIST_H
#include "fw.h"

typedef struct node_t {
	struct node_t* next;
	struct node_t* prev;
	log_row_t* log;
} node_t;

node_t* init_node(void);

int assign_log(node_t* node,log_row_t* log);

void destroy_node(node_t* node);

void remove_node(node_t* node);

int add_after(node_t* new,node_t* node);

node_t* copy_node(node_t* node);

node_t* find_node(node_t* head,node_t* query, int (*compare_func)(node_t*,node_t*));

#endif