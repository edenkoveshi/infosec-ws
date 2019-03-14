#include "conn_table.h"


static conn_list_t** table;


unsigned int joaat_hash(unsigned char *key, size_t len) //https://en.wikibooks.org/wiki/Data_Structures/Hash_Tables
  {
    unsigned int hash = 0;
    size_t i;

    for (i = 0; i < len; i++)
    {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash%TABLE_SIZE;
}

void init_conn_table(void){
  table = kmalloc(sizeof(conn_list_t*) * TABLE_SIZE,GFP_ATOMIC);
  /*if(!table){
    printk(KERN_INFO "error allocating memory");
    exit(0);
  }*/
}

void clean_conn_table(void){
  int i=0;
  conn_list_t* list;
  conn_list_t* _list;
  if(table == NULL) return;
  while((table+i) !=NULL && *(table + i) != NULL){
    list = *(table + i);
    while(list != NULL){
      _list = list;
      list = list->next;
      kfree(_list);
    }
    kfree(table + i);
  }    
}

conn_t* lookup(conn_t* conn,int (*compare_func)(conn_t*,conn_t*)){
  unsigned char* key;
  unsigned int idx;
  conn_list_t* res;
  conn_list_t* temp;
  int i = 0;

  if(!conn || !compare_func || !table) return NULL;

  key = kmalloc(6*2 + 11*2 + 10,GFP_ATOMIC); //ip*2 and port*2
  if(!key) return NULL;
  snprintf(key,6*2+11*2,"%u%u%u%u",conn->src_ip,conn->src_port,conn->dst_ip,conn->dst_port);
  idx = joaat_hash(key,strlen(key));
  kfree(key);

  res = *(table + idx);
  //printk(KERN_INFO "checking if res is null,idx is %u\n",idx);
  if(res == NULL){
    printk("res is null");
    return NULL;
  }

  //printk(KERN_INFO "conn is %u,%u,%u,%u\n",conn->src_ip,conn->dst_ip,conn->src_port,conn->dst_port);



  while(res != NULL){
    /*if(conn->timeout > res->conn->timeout && res->conn->timeout != 0){ //as conn is a new connection, timeout represents it's time of creation, which is the current time
        temp = res->next;
        destroy_conn_node(res);
        res = temp;
        continue;
    }*/

    //printk(KERN_INFO "node %d",i);

    //printk(KERN_INFO "found %u,%u,%u,%u\n",res->conn->src_ip,res->conn->dst_ip,res->conn->src_port,res->conn->dst_port);

    if(res == NULL){
      printk(KERN_INFO "res is null\n");
    }

    else if(res->conn == NULL){
      printk(KERN_INFO "res_conn is null\n");
    }


    if(compare_func(res->conn,conn) == SUCCESS){ //MATCH
      return res->conn;
    }

    res = res->next;
    i++;
  }

  printk(KERN_INFO "not found\n");
  return NULL;
}

void remove_conn_from_table(conn_t* conn,int (*compare_func)(conn_t*,conn_t*)){
  unsigned char* key;
  unsigned int idx;
  conn_list_t* res;
  if(!conn) return;

  key = kmalloc(6*2 + 11*2 + 10,GFP_ATOMIC); //ip*2 and port*2
  if(!key) return;
  snprintf(key,6*2+11*2,"%u%u%u%u",conn->src_ip,conn->src_port,conn->dst_ip,conn->dst_port);
  idx = joaat_hash(key,strlen(key));
  kfree(key);

  if(*(table + idx) == NULL) return;

  res = *(table + idx);

  while(res != NULL){
    if(compare_func(res->conn,conn) == SUCCESS){ //MATCH
      destroy_conn_node(res);
      return;
    }

    res = res->next;
  }
}


int update_table(conn_t* new,conn_t* conn_in_table,conn_t* rev){
  if(!new || !conn_in_table || !rev) return ERROR;
  printk(KERN_INFO "new: %d, conn_in_table state: %d,rev: %d",new->state,conn_in_table->state,rev->state);
  printk(KERN_INFO "I love you");
  switch(new->state){
    case TCP_ACK:
      if(conn_in_table->state == TCP_CONN_ESTABLISHED && rev->state == TCP_CONN_ESTABLISHED) return SUCCESS;
      
      if(conn_in_table->state == TCP_HANDSHAKE_SYN && rev->state == TCP_HANDSHAKE_SYN_ACK){
        conn_in_table->state = TCP_CONN_ESTABLISHED;
        rev->state = TCP_CONN_ESTABLISHED;
        return SUCCESS;
      }
      else if(conn_in_table->state == TCP_FIN && rev->state == TCP_FIN){
        remove_conn_from_table(conn_in_table,compare_conn);
        remove_conn_from_table(rev,compare_conn);
        return SUCCESS;
      }
      break;
    case TCP_FIN:
      if(conn_in_table->state == TCP_FIN) return ERROR; //can't send packets
      conn_in_table->state = TCP_FIN;
      return SUCCESS;
      break;
    default: //should not reach syn or syn ack
      return ERROR;
      break;
  }

  return ERROR;
}


int add_connection(conn_t* conn){
  unsigned char* key;
  unsigned int idx;
  conn_list_t* res;
  //conn_list_t** s;
  if(!conn) return ERROR;
  key = kmalloc(6*2 + 11*2 + 10,GFP_ATOMIC); //ip*2 and port*2
  if(!key) return ERROR;
  snprintf(key,6*2+11*2,"%u%u%u%u",conn->src_ip,conn->src_port,conn->dst_ip,conn->dst_port);
  idx = joaat_hash(key,strlen(key));
  kfree(key);

  printk(KERN_INFO "inserting, idx is %d\n",idx);

  res = *(table + idx);

  if(res == NULL){
      res = kmalloc(sizeof(conn_list_t),GFP_ATOMIC);
      if(res == NULL){
        printk(KERN_INFO "kmalloc failed\n");
        return ERROR;
      }
      res->conn = conn;
      *(table + idx) = res;
  }

  else{
    //res = *s;
    while(res != NULL){
      res = res->next;
    }
    add_after_conn_node(res,conn);
  }
  return SUCCESS; 
}

/*ssize_t table_show(struct device *dev, struct device_attribute *attr, char *buf) //sysfs show implementation
{
  return scnprintf(buf, 1,"%u\n",1);
}*/