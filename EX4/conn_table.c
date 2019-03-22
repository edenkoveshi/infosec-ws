#include "conn_table.h"


static conn_list_t* table[TABLE_SIZE];
static int cur_conn_num = 0;
static int num_conns = 0;


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
  //table = kmalloc(sizeof(conn_list_t*) * TABLE_SIZE,GFP_ATOMIC);
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
  while(table[i] != NULL){
    printk(KERN_INFO"clearing conn %d",i);
    list = table[i];
    remove_conn_from_table(list,compare_conn);
    printk(KERN_INFO"cleared conn %d",i);
    i++;
  }
  kfree(table);   
}

conn_t* lookup(conn_t* conn,int (*compare_func)(conn_t*,conn_t*)){
  int idx;
  conn_list_t* res;
  conn_list_t* temp;
  int i = 0;

  if(!conn || !compare_func || !table) return NULL;

  idx = compute_idx(conn);
  if(idx == ERROR) return ERROR;
  //idx = joaat_hashs("23554645454",strlen("23554645454"));

  res = table[idx];
  //printk(KERN_INFO "checking if res is null,idx is %u\n",idx);
  if(res == NULL){
    printk(KERN_INFO "res is null");
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

    /*if(res == NULL){
      printk(KERN_INFO "res is null\n");
      return NULL;
    }*/

    /*else if(res->conn == NULL){
      printk(KERN_INFO "res_conn is null\n");
      return NULL;
    }*/


    if(compare_func(res->conn,conn) == SUCCESS){ //MATCH
      return res->conn;
    }

    res = res->next;
    i++;
  }

  printk(KERN_INFO "not found\n");
  return NULL;
}

int remove_conn_from_table(conn_t* conn,int (*compare_func)(conn_t*,conn_t*)){
  conn_list_t* res;
  conn_list_t* prev = NULL;
  int idx;
  if(!conn || !compare_func) return ERROR;

  idx = compute_idx(conn);
  if(idx == ERROR) return ERROR;
  //idx = joaat_hash("23554645454",strlen("23554645454"));

  if(table[idx] == NULL) return ERROR;

  res = table[idx];

  while(res != NULL){
    if(res->conn != NULL && compare_func(res->conn,conn) == SUCCESS){ //MATCH
      destroy_conn_node(res,prev);
      printk(KERN_INFO "successfully removed from connection table");
      num_conns--;
      return SUCCESS;
    }
    prev = res;
    res = res->next;
    
  }
  printk(KERN_INFO "connection to remove was not found in connection table");
  return ERROR;
}


int update_table(conn_t* new,conn_t* conn_in_table,conn_t* rev){
  if(!new || !conn_in_table || !rev) return ERROR;
  printk(KERN_INFO "new: %d, conn_in_table state: %d,rev: %d",new->state,conn_in_table->state,rev->state);
  //printk(KERN_INFO "I love you");
  switch(new->state){
    case TCP_ACK:
      if(conn_in_table->state == TCP_CONN_ESTABLISHED && rev->state == TCP_CONN_ESTABLISHED) return SUCCESS;
      
      if(conn_in_table->state == TCP_HANDSHAKE_SYN && rev->state == TCP_HANDSHAKE_SYN_ACK){
        conn_in_table->state = TCP_CONN_ESTABLISHED;
        rev->state = TCP_CONN_ESTABLISHED;
        return SUCCESS;
      }
      else if(rev->state == TCP_FIN && conn_in_table->state == TCP_FIN){ //final ack
          return remove_conn_from_table(conn_in_table,compare_conn) & remove_conn_from_table(rev,compare_conn);
          //return SUCCESS;
      }

      else if(rev->state == TCP_FIN) return SUCCESS;
      break;
    case TCP_FIN:
      if(conn_in_table->state == TCP_FIN) return ERROR; //can't send packets
      conn_in_table->state = TCP_FIN;
      /*remove_conn_from_table(conn_in_table,compare_conn);
      remove_conn_from_table(rev,compare_conn);*/
      return SUCCESS;
      break;
    default: //should not reach syn or syn ack
      return ERROR;
      break;
  }

  return ERROR;
}


int add_connection(conn_t* conn){
  int idx;
  conn_list_t* res;
  conn_list_t* prev;
  //conn_list_t** s;
  int i=1;
  idx = compute_idx(conn);
  //idx = joaat_hash("23554645454",strlen("23554645454"));
  if(idx == ERROR) return ERROR;

  printk(KERN_INFO "inserting, idx is %d\n",idx);

  if(table[idx] == NULL){
     table[idx] = init_conn_node(conn);
      if(table[idx] == NULL){
        printk(KERN_INFO "kmalloc failed\n");
        return ERROR;
      }
      //res->conn = conn;
      //table[idx] = res;
      //table[idx]->next = res->next;
      //table[idx]->conn = conn;
  }

  /*res = table[idx];
  //res = NULL;

  if(res == NULL){
      res = kmalloc(sizeof(conn_list_t),GFP_ATOMIC);
      if(res == NULL){
        printk(KERN_INFO "kmalloc failed\n");
        return ERROR;
      }
      res->conn = conn;
      table[idx] = res;
  }*/

  else{
    //res = *s;

    res = table[idx];
    prev = NULL;
    while(res->next != NULL){
      printk(KERN_INFO "found %d nodes",i);
      prev = res;
      res = res->next;
      i++;
    }
    //res->next = kmalloc(sizeof(conn_list_t),GFP_ATOMIC);
    printk(KERN_INFO "finished traversing list\n");
    if(res == NULL){
      printk(KERN_INFO "res is nll after traversing list\n");
    }

    if(res->conn == NULL){
      res->conn = conn;
      //num_conns++;
      return SUCCESS;
    }
    
    if(add_after_conn_node(res,conn) == ERROR){
      return ERROR;
    }
  }

  printk(KERN_INFO "finished add_connection");

  num_conns++;
  return SUCCESS; 
}

ssize_t show_conn(struct device *dev, struct device_attribute *attr, char *buf) //sysfs show implementation
{
  int i = 0;
  int j = 0;
  conn_list_t* list;
  conn_list_t* prev = NULL;
  char conn_str[MAX_CONN_STR_SIZE];
  conn_t* conn;
  char* src_ip;
  char* dst_ip;
  while(i < TABLE_SIZE && j < cur_conn_num + 1){
    printk(KERN_INFO "here, i=%u,j=%u",i,j);
    if(table[i] != NULL){
      list = table[i];
      while(list != NULL && j < cur_conn_num + 1){
        prev = list;
        j++;
        list = list->next;
      }
    }
    i++;
  }

  if(!prev){
    return scnprintf(buf,10,"%s","ERROR1");
  }
  conn = prev->conn;

  if(!conn){
    return scnprintf(buf,1,"%s","\0");
  }

  src_ip = kmalloc(19,GFP_ATOMIC);
  dst_ip = kmalloc(19,GFP_ATOMIC);

  if(ip_to_string(conn->src_ip,src_ip) == ERROR){
      kfree(src_ip);
      kfree(dst_ip);
      return scnprintf(buf,5,"%s","ERROR3");
  }

  if(ip_to_string(conn->dst_ip,dst_ip) == ERROR){
      kfree(src_ip);
      kfree(dst_ip);
      return scnprintf(buf,5,"%s","ERROR4");
  }

  snprintf(conn_str,MAX_CONN_STR_SIZE,"%s %u %s %u %u",src_ip,conn->src_port,dst_ip,conn->dst_port,conn->state);
  return scnprintf(buf,MAX_CONN_STR_SIZE,"%s",conn_str);


}

ssize_t set_conn(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)  //sysfs store implementation
{

  int temp;
  int i = sscanf(buf, "%u", &temp);
  if(temp < TABLE_SIZE) cur_conn_num = temp;
  return count;
}

ssize_t show_conn_tab_size(struct device *dev, struct device_attribute *attr, char *buf) //sysfs show implementation
{
  return scnprintf(buf,10,"%u\n",num_conns);
}


int compute_idx(conn_t* conn){
  unsigned char* key;
  unsigned int idx;
  if(!conn) return ERROR;
  key = kmalloc(5*2 + 10*2,GFP_ATOMIC); //ip*2 and port*2
  if(!key) return ERROR;
  snprintf(key,5*2+10*2,"%u%u%u%u",conn->src_ip,conn->src_port,conn->dst_ip,conn->dst_port);
  idx = joaat_hash(key,strlen(key));
  kfree(key);
  return idx;
}