obj-m := firewall.o
firewall-objs := sha1.o conn.o conn_table.o list.o fw_log.o fw_rules.o fw.o
EXTRA_CFLAGS += -I$(src)
sha1.o: sha1.h
list.o: list.h
fw_log.o: fw_log.h list.o
conn.o: conn.h fw.h
conn_table.o: conn_table.h conn.o fw_log.o sha1.o
fw_rules.o: fw_rules.h fw_log.o conn_table.o
fw.o: fw.h fw_rules.o

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules