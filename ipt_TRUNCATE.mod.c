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
	{ 0xef0eea15, "module_layout" },
	{ 0x608c1034, "xt_register_target" },
	{ 0x2124474, "ip_send_check" },
	{ 0x716de2c2, "skb_trim" },
	{ 0xe113bbbc, "csum_partial" },
	{ 0x527a340f, "nf_ip_checksum" },
	{ 0x405480cf, "skb_copy_bits" },
	{ 0x44a78e94, "___pskb_trim" },
	{ 0xea147363, "printk" },
	{ 0x6dd4bda4, "xt_unregister_target" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=x_tables";

