sudo rmmod firewall
make clean
make all
sudo insmod firewall.ko
gcc user.c -o main