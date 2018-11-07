obj-m += hw2secws.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc hw2client.c -o hw2client

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm hw2client.o
