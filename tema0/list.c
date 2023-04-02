// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Bogdan-Mihai Tudorache <bogdanmihait10@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

#define MAX_STRLEN 81

#define ADD_FRONT "addf "
#define ADD_END "adde "
#define DEL_FIRST "delf "
#define DEL_ALL "dela "

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

struct string_node {
	char string[MAX_STRLEN];
	struct list_head list;
};

LIST_HEAD(string_list);

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *runner;
	struct string_node *node;

	list_for_each(runner, &string_list) {
		node = list_entry(runner, struct string_node, list);
		seq_puts(m, node->string);
		seq_puts(m, "\n");
	}

	return 0;
}

static struct string_node *string_node_alloc(char *str)
{
	struct string_node *node;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (node == NULL)
		return NULL;

	strncpy(node->string, str, MAX_STRLEN - 1);
	node->string[MAX_STRLEN - 1] = '\0';

	return node;
}

static void add_elem_to_front(char *str)
{
	struct string_node *node = string_node_alloc(str);

	list_add(&node->list, &string_list);
}

static void add_elem_to_end(char *str)
{
	struct string_node *node = string_node_alloc(str);

	list_add(&node->list, string_list.prev);
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static void delete_all_elems(char *str)
{
	char str_buffer[MAX_STRLEN];
	struct list_head *runner;
	struct list_head *tmp;
	struct string_node *node;

	memset(str_buffer, 0, MAX_STRLEN);
	strncpy(str_buffer, str, MAX_STRLEN - 1);

	list_for_each_safe(runner, tmp, &string_list) {
		node = list_entry(runner, struct string_node, list);
		if (strncmp(node->string, str_buffer, MAX_STRLEN - 1) == 0) {
			list_del(runner);
			kfree(node);
		}
	}
}

static void delete_first_elem(char *str)
{
	char str_buffer[MAX_STRLEN];
	unsigned char deleted_first = 0;
	struct list_head *runner;
	struct list_head *tmp;
	struct string_node *node;

	memset(str_buffer, 0, MAX_STRLEN);
	strncpy(str_buffer, str, MAX_STRLEN - 1);

	list_for_each_safe(runner, tmp, &string_list) {
		node = list_entry(runner, struct string_node, list);
		if (strncmp(node->string, str_buffer, MAX_STRLEN - 1) == 0 && !deleted_first) {
			list_del(runner);
			kfree(node);
			deleted_first = 1;
		}
	}
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	int i;
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	for (i = PROCFS_MAX_SIZE - 1; i >= 0; i--) {
		if (local_buffer[i] == '\n') {
			local_buffer[i] = '\0';
			break;
		}
	}

	if (strncmp(local_buffer, ADD_FRONT, strlen(ADD_FRONT)) == 0)
		add_elem_to_front(local_buffer + strlen(ADD_FRONT));
	else if (strncmp(local_buffer, ADD_END, strlen(ADD_END)) == 0)
		add_elem_to_end(local_buffer + strlen(ADD_END));
	else if (strncmp(local_buffer, DEL_FIRST, strlen(DEL_FIRST)) == 0)
		delete_first_elem(local_buffer + strlen(DEL_FIRST));
	else if (strncmp(local_buffer, DEL_ALL, strlen(DEL_ALL)) == 0)
		delete_all_elems(local_buffer + strlen(DEL_ALL));

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Bogdan-Mihai Tudorache <bogdanmihait10@gmail.com>");
MODULE_LICENSE("GPL v2");
