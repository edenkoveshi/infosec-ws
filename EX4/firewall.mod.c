#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x68d372d2, "module_layout" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0x8ad2e126, "device_remove_file" },
	{ 0x794a2c29, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xabd0c91c, "rtc_time_to_tm" },
	{ 0xd0d8621b, "strlen" },
	{ 0x6d597694, "device_destroy" },
	{ 0xf34131ee, "__register_chrdev" },
	{ 0x85df9b6c, "strsep" },
	{ 0x4a54cfda, "nf_register_hook" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xce2d8a96, "__pskb_pull_tail" },
	{ 0x2bc95bd4, "memset" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0x50eedeb8, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xb6ed1e53, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0x6c2e3320, "strncmp" },
	{ 0xc3aaf0a9, "__put_user_1" },
	{ 0xc60796c9, "device_create" },
	{ 0x2276db98, "kstrtoint" },
	{ 0xfe5d4bb2, "sys_tz" },
	{ 0x61651be, "strcat" },
	{ 0xeb987ea9, "device_create_file" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3f9b9190, "kmem_cache_alloc_trace" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0x7afa89fc, "vsnprintf" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0xbd33dff7, "nf_unregister_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0x69ad2f20, "kstrtouint" },
	{ 0xf9e73082, "scnprintf" },
	{ 0x6dcd7881, "class_destroy" },
	{ 0x7d50a24, "csum_partial" },
	{ 0x34d76c42, "__class_create" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "8F9BC462121411E8140AE79");
