#include "fw.h"
#include "fw_log.h"
#include "fw_rules.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eden Koveshi");

static struct class* sysfs_class = NULL;	// The device's class
static struct device* rules_device = NULL;	// The device's name
static struct device* log_device = NULL;

struct file_operations log_fops =
{
  .owner = THIS_MODULE,
  .read = show_logs,
  .open = device_open,
  .release = device_release,

};

static struct nf_hook_ops pkt_ops = {
    .pf = NFPROTO_IPV4,
    .priority = 1,
    .hooknum = NF_INET_FORWARD,
    .hook = hook_func,
};

static DEVICE_ATTR(log_size, S_IROTH , num_logs_show, NULL);
static DEVICE_ATTR(log_clear, S_IWOTH , NULL , clear_logs_store);
static DEVICE_ATTR(active, S_IROTH|S_IWOTH , active_show, active_store);
static DEVICE_ATTR(rules_size, S_IROTH , size_show, NULL);
static DEVICE_ATTR(add_rule,S_IWOTH, NULL, rule_store);
static DEVICE_ATTR(clear_rules,S_IWOTH, NULL, clear_rules_store);
static DEVICE_ATTR(show_rules,S_IROTH | S_IWOTH,get_rule,set_cur_rule);

static char *log_devnode(struct device *dev, umode_t *mode) //https://stackoverflow.com/questions/11846594/how-can-i-programmatically-set-permissions-on-my-char-device
{
        if (!mode)
                return NULL;
        if (dev->devt == MKDEV(MAJOR_NUM, 1))
                *mode = 0666;
        return NULL;
}

static int __init fw_init(void){
	int major_num;
	printk(KERN_INFO "Loading firewall");
	major_num = register_chrdev(MAJOR_NUM, MODULE_NAME, &log_fops);
	
	if (major_num < 0) {
		return ERROR;
	}
	
	sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
	
	if (IS_ERR(sysfs_class)) {
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	sysfs_class->devnode = log_devnode;

	rules_device = device_create(sysfs_class, NULL, MKDEV(MAJOR_NUM, MINOR_RULES), NULL, CLASS_NAME "_" DEVICE_NAME_RULES);	

	if (IS_ERR(rules_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	log_device = device_create(sysfs_class, NULL, MKDEV(MAJOR_NUM, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);	

	if (IS_ERR(log_device)) {
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM,MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr))
	{
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr))
	{
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_log_clear.attr))
	{
		device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_show_rules.attr))
	{
		device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
		device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
		device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
		device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
		class_destroy(sysfs_class);
		unregister_chrdev(MAJOR_NUM, MODULE_NAME);
		return -1;
	}

	nf_register_hook(&pkt_ops);

	clear_rules();
	add_localhost();
	add_prot_other();

	return 0;
}

static void __exit fw_exit(void){
	nf_unregister_hook(&pkt_ops);
	clear_logs();
	clear_rules();
	device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_clear.attr);
	device_remove_file(log_device, (const struct device_attribute *)&dev_attr_log_size.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_active.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_add_rule.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_clear_rules.attr);
	device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_show_rules.attr);
	device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_RULES));
	device_destroy(sysfs_class, MKDEV(MAJOR_NUM, MINOR_LOG));
	class_destroy(sysfs_class);
	unregister_chrdev(MAJOR_NUM, MODULE_NAME);
	printk(KERN_INFO "%s module removed successfully",DEVICE_NAME_LOG);
}

module_init(fw_init);
module_exit(fw_exit);