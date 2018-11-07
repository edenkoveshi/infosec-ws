#include <stdio.h>

#define ERROR -1
#define SUCCESS 0

int main(int argc,char* argv[]){
	if(argc > 2){
		printf("Invalid number of arguments\n");
		return ERROR;
	}

	else if(argc == 2){
		if(atoi(argv[1]) == 0){
			system("echo 0 > /sys/class/sniffer/pkt-sniffer/pkt_summary");
		}
		else{
			printf("Optional argument can be 0 only\n");
			return ERROR;
		}
	}

	else{
		system("cat /sys/class/sniffer/pkt-sniffer/pkt_summary");
	}

	return SUCCESS;

}