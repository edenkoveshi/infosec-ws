obj-m := firewall.o
firewall-objs := conn.o conn_table.o list.o fw_log.o fw_rules.o fw.o
EXTRA_CFLAGS += -I$(src)
list.o: list.h
fw_log.o: fw_log.h list.o
conn.o: conn.h fw.h
conn_table.o: conn_table.h conn.o
fw_rules.o: fw_rules.h fw_log.o conn_table.o
fw.o: fw.h fw_rules.o

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules