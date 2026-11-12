#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/stop_machine.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KVM-XJ：CVE-2026-53359 运行时内存热补丁");

static unsigned long target_address;
static unsigned char original_bytes[6];
static unsigned char nop_bytes[6] = {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00};

typedef void *(*text_poke_fn)(void *addr, const void *opcode, size_t len);

static int apply_patch(void *data)
{
    text_poke_fn poke = (text_poke_fn)kallsyms_lookup_name("text_poke");
    if (!poke) {
        printk(KERN_ERR "KVM-XJ：无法解析 text_poke\n");
        return -1;
    }
    memcpy(original_bytes, (void *)(target_address + 0x108), 6);
    poke((void *)(target_address + 0x108), nop_bytes, 6);
    return 0;
}

static int __init hotpatch_init(void)
{
    target_address = kallsyms_lookup_name("kvm_mmu_get_page");
    if (!target_address) {
        printk(KERN_ERR "KVM-XJ：无法解析 kvm_mmu_get_page\n");
        return -ENOENT;
    }
    printk(KERN_INFO "KVM-XJ：目标函数地址=%px\n", (void *)target_address);
    printk(KERN_INFO "KVM-XJ：正在修改偏移 0x108 处的跳转指令\n");
    stop_machine(apply_patch, NULL, NULL);
    printk(KERN_INFO "KVM-XJ：热补丁已加载\n");
    return 0;
}

static void __exit hotpatch_exit(void)
{
    text_poke_fn poke = (text_poke_fn)kallsyms_lookup_name("text_poke");
    if (target_address && poke) {
        poke((void *)(target_address + 0x108), original_bytes, 6);
        printk(KERN_INFO "KVM-XJ：热补丁已卸载，原始字节已恢复\n");
    }
}

module_init(hotpatch_init);
module_exit(hotpatch_exit);
