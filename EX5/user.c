#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define SUCCESS			 0
#define ERROR 			-1
#define MAX_RULE_STRING_SIZE 110
#define MAX_CONN_STR_SIZE	65 //19*2 + 5*2 + 2 + 4 + 1 (+10)
#define MAX_RULES		(50)
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"


void activate(int p);
int parse_load_rules(char* path);
void show_log(void);
void show_rules(void);
void show_conn_table(void);

int main(int argc,char* argv[]){
	char* command;
	if(argc > 3 || argc < 1){
		printf("Invalid number of arguments\n");
		return ERROR;
	}

	else if(argc == 3){ //load_rules <path>
		if(strcmp(argv[1],"load_rules") != 0){
			printf("Invalid command\n");
			return ERROR;
		}
		return parse_load_rules(argv[2]);
	}

	else{
		if(strcmp(argv[1],"activate") == 0){
			activate(1);
		}
		else if(strcmp(argv[1],"deactivate") == 0){
			activate(0);
		}
		else if(strcmp(argv[1],"show_rules") == 0){
			show_rules();
		}
		else if(strcmp(argv[1],"clear_rules") == 0){
			command = malloc(sizeof("echo  > /sys/class//_/clear_rules") + 1 + 2*sizeof(CLASS_NAME) + sizeof(DEVICE_NAME_RULES));
			sprintf(command,"echo c > /sys/class/%s/%s_%s/clear_rules",CLASS_NAME,CLASS_NAME,DEVICE_NAME_RULES);
			system(command);
			free(command);
		}
		else if(strcmp(argv[1],"show_log") == 0){
			show_log();
		}
		else if(strcmp(argv[1],"clear_log") == 0){
			command = malloc(sizeof("echo  > /sys/class//_/log_clear") + 1 + 2*sizeof(CLASS_NAME) + sizeof(DEVICE_NAME_LOG));
			sprintf(command,"echo c > /sys/class/%s/%s_%s/log_clear",CLASS_NAME,CLASS_NAME,DEVICE_NAME_LOG);
			system(command);
			free(command);
		}
		else if(strcmp(argv[1],"show_connection_table") == 0){
			show_conn_table();
		}
		else{
			printf("Invalid command\n");
			return ERROR;
		}
		return SUCCESS;
		
	}

	return SUCCESS;
}


int parse_load_rules(char* path){
	int fd;
	char* rule_string;
	char* rules;
	char* command;

	fd = open(path,O_RDONLY);
	if(fd < 0)
	{
		printf("Invalid file path\n");
		return ERROR;
	}

	rules = malloc(MAX_RULE_STRING_SIZE * MAX_RULES);

	if(read(fd,rules,MAX_RULE_STRING_SIZE * MAX_RULES) < 0)
	{
		perror("Error: ");
		return ERROR;
	}


	while((rule_string = strsep(&rules,"\n")) != NULL){
		command = malloc(sizeof("echo \"\" > /sys/class//_/add_rule") + MAX_RULE_STRING_SIZE + 2*strlen(CLASS_NAME) + strlen(DEVICE_NAME_RULES));
		sprintf(command,"echo \"%s\" > /sys/class/%s/%s_%s/add_rule",rule_string,CLASS_NAME,CLASS_NAME,DEVICE_NAME_RULES);
		system(command);
		free(command);
	}

	free(rules);
	return SUCCESS;
}

void activate(int p){
	char* command;
	command = malloc(sizeof("echo  > /sys/class//_/active") + 1 + 2*sizeof(CLASS_NAME) + sizeof(DEVICE_NAME_RULES));
	sprintf(command,"echo %d > /sys/class/%s/%s_%s/active",p,CLASS_NAME,CLASS_NAME,DEVICE_NAME_RULES);
	system(command);
}

void show_log(void){
	int fd;
	int _fd;
	char* buf;
	int check;
	int log_size = 6*10+15*2+6+strlen("DD/MM/YYYY hh:mm:ss")+10;
	unsigned long num_logs = 0;
	_fd = open("/sys/class/fw/fw_log/log_size",O_RDONLY);

	if(_fd < 0){
		perror("Error opening file,exiting.. :");
		return;
	}

	if(read(_fd,&num_logs,sizeof(unsigned long)) < 0){
		perror("Error reading from file, exiting..");
		close(_fd);
		return;
	}

	close(_fd);

	fd = open("/dev/fw_log",O_RDONLY);

	if(fd < 0){
		perror("Error opening file, exiting.. :");
		return;
	}

	buf = malloc(log_size*num_logs);

	if((check = read(fd,buf,log_size*num_logs)) < 0){
		perror("Error reading from file, exiting.. :");	
		free(buf);
		close(fd);
		return;
	}

	else{
		printf("%s",buf);
	}

	free(buf);
	close(fd);
}


void show_rules(void){
	int fd;
	int _fd;
	char buf[MAX_RULE_STRING_SIZE];
	int check;
	unsigned int cur_rule;
	unsigned int num_rules = 0;
	char num_string[10] = {0}; //assuming MAX_RULES is integer
	
	_fd = open("/sys/class/fw/fw_rules/rules_size",O_RDONLY); 
	if(_fd < 0){
		perror("Error opening file,exiting.. :");
		return;
	}

	if(read(_fd,&buf,sizeof(unsigned long)) < 0){
		perror("Error reading from file, exiting..");
		close(_fd);
		return;
	}

	close(_fd);

	num_rules = atoi(buf);
	if(num_rules == 0) //it can never be 0, thus it implies atoi has failed
	{
		perror("Error reading from file, exiting..");
		return;	
	}

	for(cur_rule = 0;cur_rule < num_rules;cur_rule++){
		memset(buf,0,MAX_RULE_STRING_SIZE);

		fd = open("/sys/class/fw/fw_rules/show_rules",O_RDWR);

		if(fd < 0){
			perror("Error opening file,exiting.. :");
			return;
		}

		sprintf(num_string,"%u",cur_rule);

		if(write(fd,num_string,strlen(num_string)) < 0){
			perror("Error writing file, exiting..");
			close(fd);
			return;
		}

		if((check = read(fd,buf,MAX_RULE_STRING_SIZE)) < 0){
			perror("Error reading from file, exiting.. :");	
			close(fd);
			return;
		}

		printf("%s\n",buf);

		close(fd);
	}	
}


void show_conn_table(void){
	int fd;
	int _fd;
	char buf[MAX_CONN_STR_SIZE];
	int check;
	unsigned int cur_conn;
	unsigned int num_conns = 0;
	char num_string[10] = {0}; //assuming TABLE_SIZE is integer
	
	_fd = open("/sys/class/fw/fw_conn_tab/show_conn_table_size",O_RDONLY); 
	if(_fd < 0){
		perror("Error opening file,exiting.. :");
		return;
	}

	if(read(_fd,&buf,sizeof(unsigned long)) < 0){
		perror("Error reading from file, exiting..");
		close(_fd);
		return;
	}

	close(_fd);

	num_conns = atoi(buf);
	if(num_conns == 0) //it can never be 0, thus it implies atoi has failed
	{
		printf("Connection table is empty\n");
		return;	
	}

	

	printf("table size %u\n",num_conns);

	for(cur_conn = 0;cur_conn < num_conns;cur_conn++){
		memset(buf,0,MAX_CONN_STR_SIZE);
		memset(num_string,0,10);

		fd = open("/sys/class/fw/fw_conn_tab/show_conn_table",O_RDWR);

		if(fd < 0){
			perror("Error opening file,exiting.. :");
			return;
		}

		sprintf(num_string,"%u\n",cur_conn);

		if(write(fd,num_string,strlen(num_string)) < 0){
			perror("Error writing file, exiting..");
			close(fd);
			return;
		}

		//printf("wrote conn num %u\n",cur_conn);

		if((check = read(fd,buf,MAX_CONN_STR_SIZE)) < 0){
			printf("Connection table is empty");	
			close(fd);
			return;
		}

		//if(strcmp(buf,"ERROR")) 
		printf("%s\n",buf);

		close(fd);
	}	
}