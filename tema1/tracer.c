// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Bogdan-Mihai Tudorache <bogdanmihait10@gmail.com>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/miscdevice.h>

#include "tracer.h"


#define PROCFS_TRACER_READ	"tracer"

#define NUM_FUNCTIONS_RECORDED 7
#define NUM_MEMORY_OPS_VALUES 2

#define KMALLOC_KEY 0
#define KFREE_KEY 1
#define SCHED_KEY 2
#define UP_KEY 3
#define DOWN_KEY 4
#define LOCK_KEY 5
#define UNLOCK_KEY 6
#define BASE_ERROR_CODE -1

#define MAX_KRETPROBE_ACTIVE 64

#define BUFFER_SIZE 4096 * 4
#define TRACER_PRINT_STRING_FORMATTER "%-5s%-10s%-10s%-15s%-15s%-10s%-8s%-8s%-8s%-10s\n"
#define TRACER_PRINT_INT_FORMATTER "%-5d%-10d%-10d%-15d%-15d%-10d%-8d%-8d%-8d%-10d\n"

static char kmalloc_func_name[NAME_MAX] = "__kmalloc";
static char kfree_func_name[NAME_MAX] = "kfree";
static char sched_func_name[NAME_MAX] = "schedule";
static char up_func_name[NAME_MAX] = "up";
static char down_func_name[NAME_MAX] = "down_interruptible";
static char lock_func_name[NAME_MAX] = "mutex_lock_nested";
static char unlock_func_name[NAME_MAX] = "mutex_unlock";

static char exit_func_name[NAME_MAX] = "do_exit";

struct proc_dir_entry *proc_list_read;


struct process_node {
	pid_t pid;
	int calls_recorded[NUM_FUNCTIONS_RECORDED];
	size_t memory_recorded[NUM_MEMORY_OPS_VALUES];
	struct list_head list;
};

LIST_HEAD(process_list);

struct memory_map_node {
	void *kmalloc_address;
	size_t kmalloc_size;
	struct list_head list;
};

LIST_HEAD(memory_map_list);

/* per-instance private data */
struct kmalloc_probe_data {
	size_t kmalloc_size;
};

static struct memory_map_node *memory_map_node_alloc(void *kmalloc_address, size_t kmalloc_size)
{
	struct memory_map_node *node;

	node = kmalloc(sizeof(*node), GFP_ATOMIC);

	if (node == NULL)
		return NULL;

	memset(node, 0, sizeof(*node));
	node->kmalloc_address = kmalloc_address;
	node->kmalloc_size = kmalloc_size;

	return node;
}

static void add_memory_map_elem(void *kmalloc_address, size_t kmalloc_size)
{
	struct memory_map_node *node = memory_map_node_alloc(kmalloc_address, kmalloc_size);

	list_add(&node->list, &memory_map_list);
}

static struct process_node *process_node_alloc(pid_t pid)
{
	struct process_node *node;

	node = kmalloc(sizeof(*node), GFP_ATOMIC);
	if (node == NULL)
		return NULL;

	memset(node->calls_recorded, 0, NUM_FUNCTIONS_RECORDED * sizeof(int));
	memset(node->memory_recorded, 0, NUM_MEMORY_OPS_VALUES * sizeof(int));
	node->pid = pid;

	return node;
}

static void add_process_elem(pid_t pid)
{
	struct process_node *node = process_node_alloc(pid);

	list_add(&node->list, &process_list);
}

static void remove_process_elem(pid_t pid)
{
	struct list_head *runner;
	struct list_head *tmp;
	struct process_node *node;

	list_for_each_safe(runner, tmp, &process_list) {
		node = list_entry(runner, struct process_node, list);
		if (node->pid == pid) {
			list_del(runner);
			kfree(node);
		}
	}
}

static int tracer_print(struct seq_file *m, void *v)
{
	char *print_buffer;
	struct list_head *runner;
	struct process_node *node;

	print_buffer = kmalloc(BUFFER_SIZE * sizeof(char), GFP_ATOMIC);
	memset(print_buffer, 0, BUFFER_SIZE * sizeof(char));

	sprintf(print_buffer, TRACER_PRINT_STRING_FORMATTER,
			"PID", "kmalloc", "kfree", "kmalloc_mem", "kfree_mem",
			"sched", "up", "down", "lock", "unlock");

	list_for_each(runner, &process_list) {
		node = list_entry(runner, struct process_node, list);
		sprintf(print_buffer + strlen(print_buffer), TRACER_PRINT_INT_FORMATTER,
				node->pid,
				node->calls_recorded[KMALLOC_KEY],
				node->calls_recorded[KFREE_KEY],
				node->memory_recorded[KMALLOC_KEY],
				node->memory_recorded[KFREE_KEY],
				node->calls_recorded[SCHED_KEY],
				node->calls_recorded[UP_KEY],
				node->calls_recorded[DOWN_KEY],
				node->calls_recorded[LOCK_KEY],
				node->calls_recorded[UNLOCK_KEY]);
	}

	seq_puts(m, print_buffer);
	return 0;
}

static int tracer_print_wrapper(struct inode *inode, struct  file *file)
{
	return single_open(file, tracer_print, NULL);
}

static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		add_process_elem((pid_t) arg);
		break;
	case TRACER_REMOVE_PROCESS:
		remove_process_elem((pid_t) arg);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tracer_ioctl
};

struct miscdevice tracer_device = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_fops,
};

// generic calls tracer recorder (for all traced functions)
static void generic_calls_recorder(pid_t pid, int function_key)
{
	struct list_head *runner;
	struct process_node *node;

	list_for_each(runner, &process_list) {
		node = list_entry(runner, struct process_node, list);
		if (node->pid == pid)
			node->calls_recorded[function_key] += 1;
	}
}

// generic allocations tracer recorder (for all allocated resources)
static void generic_allocs_recorder(pid_t pid, int function_key, size_t size)
{
	struct list_head *runner;
	struct process_node *node;

	list_for_each(runner, &process_list) {
		node = list_entry(runner, struct process_node, list);
		if (node->pid == pid)
			node->memory_recorded[function_key] += size;
	}
}


// kmalloc kretprobe handlers and data
static int kmalloc_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmalloc_probe_data *data;

	generic_calls_recorder(current->pid, KMALLOC_KEY);
	generic_allocs_recorder(current->pid, KMALLOC_KEY, (size_t) regs->ax);

	data = (struct kmalloc_probe_data *)ri->data;
	data->kmalloc_size = (size_t) regs->ax;

	return 0;
}


static int kmalloc_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmalloc_probe_data *data;
	void *kmalloc_address;

	if (ri == NULL || regs == NULL)
		return BASE_ERROR_CODE;

	kmalloc_address = (void *) regs_return_value(regs);
	if (kmalloc_address == NULL)
		return BASE_ERROR_CODE;

	data = (struct kmalloc_probe_data *)ri->data;
	if (data == NULL)
		return BASE_ERROR_CODE;

	add_memory_map_elem(kmalloc_address, data->kmalloc_size);
	return 0;
}

static struct kretprobe kmalloc_kretprobe = {
	.entry_handler	= kmalloc_entry_handler,
	.handler		= kmalloc_ret_handler,
	.data_size		= sizeof(struct kmalloc_probe_data),
	.maxactive		= MAX_KRETPROBE_ACTIVE,
};

// kfree kretprobe handlers and data
static int kfree_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct list_head *runner;
	struct list_head *tmp;
	struct memory_map_node *node;
	void *kfree_address = (void *) regs->ax;

	if (regs == NULL)
		return BASE_ERROR_CODE;

	generic_calls_recorder(current->pid, KFREE_KEY);

	if (kfree_address != NULL) {
		list_for_each_safe(runner, tmp, &memory_map_list) {
			node = list_entry(runner, struct memory_map_node, list);
			if (node->kmalloc_address == kfree_address) {
				generic_allocs_recorder(current->pid, KFREE_KEY, node->kmalloc_size);
				list_del(runner);
				kfree(node);
			}
		}
	}

	return 0;
}

static struct kretprobe kfree_kretprobe = {
	.entry_handler = kfree_entry_handler,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

// sched kretprobe handlers and data
static int sched_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	generic_calls_recorder(current->pid, SCHED_KEY);
	return 0;
}

static struct kretprobe sched_kretprobe = {
	.entry_handler = sched_entry_handler,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

// up kretprobe handlers and data
static int up_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	generic_calls_recorder(current->pid, UP_KEY);
	return 0;
}

static struct kretprobe up_kretprobe = {
	.entry_handler = up_entry_handler,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

// down kretprobe handlers and data
static int down_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	generic_calls_recorder(current->pid, DOWN_KEY);
	return 0;
}

static struct kretprobe down_kretprobe = {
	.entry_handler = down_entry_handler,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

// lock kretprobe handlers and data
static int lock_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	generic_calls_recorder(current->pid, LOCK_KEY);
	return 0;
}

static struct kretprobe lock_kretprobe = {
	.entry_handler = lock_entry_handler,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

// unlock kretprobe handlers and data
static int unlock_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	generic_calls_recorder(current->pid, UNLOCK_KEY);
	return 0;
}

static struct kretprobe unlock_kretprobe = {
	.entry_handler = unlock_entry_handler,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};

// do_exit kretprobe handlers and data
static int exit_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	remove_process_elem((pid_t)current->pid);
	return 0;
}

static struct kretprobe exit_kretprobe = {
	.entry_handler = exit_entry_handler,
	.maxactive = MAX_KRETPROBE_ACTIVE,
};


static const struct proc_ops r_pops = {
	.proc_open		= tracer_print_wrapper,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static int tracer_init(void)
{
	int error;

	// register misc device
	error = misc_register(&tracer_device);
	if (error)
		return error;

	// register /proc entry
	proc_list_read = proc_create(PROCFS_TRACER_READ, 0000, NULL, &r_pops);
	if (!proc_list_read)
		return -ENOMEM;

	// register probes
	kmalloc_kretprobe.kp.symbol_name = kmalloc_func_name;
	error = register_kretprobe(&kmalloc_kretprobe);
	if (error < 0)
		return BASE_ERROR_CODE;

	kfree_kretprobe.kp.symbol_name = kfree_func_name;
	error = register_kretprobe(&kfree_kretprobe);
	if (error < 0)
		return BASE_ERROR_CODE;

	sched_kretprobe.kp.symbol_name = sched_func_name;
	error = register_kretprobe(&sched_kretprobe);
	if (error < 0)
		return BASE_ERROR_CODE;

	up_kretprobe.kp.symbol_name = up_func_name;
	error = register_kretprobe(&up_kretprobe);
	if (error < 0)
		return BASE_ERROR_CODE;

	down_kretprobe.kp.symbol_name = down_func_name;
	error = register_kretprobe(&down_kretprobe);
	if (error < 0)
		return BASE_ERROR_CODE;

	lock_kretprobe.kp.symbol_name = lock_func_name;
	error = register_kretprobe(&lock_kretprobe);
	if (error < 0)
		return BASE_ERROR_CODE;

	unlock_kretprobe.kp.symbol_name = unlock_func_name;
	error = register_kretprobe(&unlock_kretprobe);
	if (error < 0)
		return BASE_ERROR_CODE;


	exit_kretprobe.kp.symbol_name = exit_func_name;
	error = register_kretprobe(&exit_kretprobe);
	if (error < 0)
		return BASE_ERROR_CODE;

	return 0;
}

static void tracer_exit(void)
{
	// unregister misc device
	misc_deregister(&tracer_device);

	// unregister /proc entry
	proc_remove(proc_list_read);

	// unregister probes
	unregister_kretprobe(&kmalloc_kretprobe);
	unregister_kretprobe(&kfree_kretprobe);
	unregister_kretprobe(&sched_kretprobe);
	unregister_kretprobe(&up_kretprobe);
	unregister_kretprobe(&down_kretprobe);
	unregister_kretprobe(&lock_kretprobe);
	unregister_kretprobe(&unlock_kretprobe);

	unregister_kretprobe(&exit_kretprobe);
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Bogdan-Mihai Tudorache");
MODULE_LICENSE("GPL v2");
