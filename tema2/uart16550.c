// SPDX-License-Identifier: GPL-2.0+

/*
 * uart16550.c - Driver implementation for the 16550 UART.
 *
 * Author: Bogdan-Mihai Tudorache <bogdanmihait10@gmail.com>
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/io.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/moduleparam.h>

#include "uart16550.h"

#define MODULE_NAME		"uart16550"
#define OPTION_BOTH_STRING	"OPTION_BOTH"
#define OPTION_COM1_STRING	"OPTION_COM1"
#define OPTION_COM2_STRING	"OPTION_COM2"

#define COM1_ADDR 0x3f8
#define COM2_ADDR 0x2f8
#define NUM_PORTS 8

#define COM1_PORT_NAME "COM1"
#define COM2_PORT_NAME "COM2"

#define IRQ_COM1 4
#define IRQ_COM2 3

#define COM1_DEVICE_NUM 0
#define COM2_DEVICE_NUM 1

#define FIFO_SIZE	512
#define MINOR_NUM	0

static int MAJOR = 42;
static char* OPTION = OPTION_BOTH_STRING;
static int option = OPTION_BOTH;

module_param(MAJOR, int, 0000);
MODULE_PARM_DESC(MAJOR, "Device major version");

module_param(OPTION, charp, 0000);
MODULE_PARM_DESC(OPTION, "Options for using the device ports");


struct uart16550_data {
	struct cdev cdev;
	int device_num;
	spinlock_t lock;
	// TODO: see if atomic_t types are needed (kfifo type should already have synchonized methods)
	atomic_t read_buffer_size, write_buffer_size;
    wait_queue_head_t wq_reads, wq_writes;
	DECLARE_KFIFO(read_fifo, unsigned char, FIFO_SIZE)
	DECLARE_KFIFO(write_fifo, unsigned char, FIFO_SIZE)
} devs[MAX_NUMBER_DEVICES];


/*
 * Return the value of the DATA register.
 */
static inline u8 i8042_read_data(void)
{
	// u8 val;
	// val = inb(I8042_DATA_REG);
	// return val;
	return 0;
}


irqreturn_t uart16550_interrupt_handle(int irq_no, void *dev_id)
{
	// TODO: A lot to do here;
	// - see which port is accesed
	// - detect and handle read or write interrupts
	// - notify finished intrerupt

	// unsigned int scancode = 0;
	// int pressed, ch;

	// scancode = i8042_read_data();
	// pressed = is_key_press(scancode);
	// ch = get_ascii(scancode);

	// pr_info("IRQ %d: scancode=0x%x (%u) pressed=%d ch=%c\n",
	// 	irq_no, scancode, scancode, pressed, ch);

	// if (pressed) {
	// 	struct uart16550 *data = (struct uart16550 *)dev_id;

	// 	spin_lock(&data->lock);
	// 	put_char(data, ch);
	// 	spin_unlock(&data->lock);
	// }

	return IRQ_NONE;
}

static int uart16550_open(struct inode *inode, struct file *file)
{
	struct uart16550 *data = container_of(inode->i_cdev, struct uart16550, cdev);
	file->private_data = data;
	pr_info("%s opened\n", MODULE_NAME);
	return 0;
}

static int uart16550_release(struct inode *inode, struct file *file)
{
	pr_info("%s closed\n", MODULE_NAME);
	return 0;
}

/* TODO 5/12: add write operation and reset the buffer */
static ssize_t uart16550_write(struct file *file, const char __user *user_buffer,
			 size_t size, loff_t *offset)
{
	struct uart16550 *data = (struct uart16550 *) file->private_data;
	unsigned long flags;

	spin_lock_irqsave(&data->lock, flags);
	// reset_buffer(data);
	spin_unlock_irqrestore(&data->lock, flags);

	return size;
}

static ssize_t uart16550_read(struct file *file,  char __user *user_buffer,
			size_t size, loff_t *offset)
{
	struct uart16550 *data = (struct uart16550 *) file->private_data;
	size_t read = 0;
	/* TODO 4/18: read data from buffer */
	unsigned long flags;
	char ch;
	bool more = true;

	while (size--) {
		spin_lock_irqsave(&data->lock, flags);
		// more = get_char(&ch, data);
		spin_unlock_irqrestore(&data->lock, flags);
		read++;
	}

	return read;
}

static long uart16550_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
	case UART16550_IOCTL_SET_LINE:
		// TODO: complete this
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations uart16550_fops = {
	.owner = THIS_MODULE,
	.open = uart16550_open,
	.release = uart16550_release,
	.read = uart16550_read,
	.write = uart16550_write,
	.unlocked_ioctl = uart16550_ioctl
};

static int uart16550_init(void)
{
	int err;
	int num_minors = MAX_NUMBER_DEVICES;

	if (strncmp(OPTION, OPTION_BOTH_STRING, strlen(OPTION_BOTH_STRING)) == 0) {
		option = OPTION_BOTH;
		num_minors = MAX_NUMBER_DEVICES
	} else if (strncmp(OPTION, OPTION_COM1_STRING, strlen(OPTION_COM1_STRING)) == 0) {
		option = OPTION_COM1;
		num_minors = 1;
	} else if (strncmp(OPTION, OPTION_COM2_STRING, strlen(OPTION_COM2_STRING)) == 0) {
		option = OPTION_COM2
		num_minors = 1;
	}

	err = register_chrdev_region(MKDEV(MAJOR, MINOR_NUM), num_minors, MODULE_NAME);
	if (err != 0) {
		pr_err("register_region failed: %d\n", err);
		goto out;
	}

	if (option == OPTION_BOTH) {
		if (request_region(COM1_ADDR, NUM_PORTS, COM1_PORT_NAME) == NULL) {
			err = -EBUSY;
			goto out_unregister;
		}

		if (request_region(COM2_ADDR, NUM_PORTS, COM2_PORT_NAME) == NULL) {
			err = -EBUSY;
			goto out_release_region;
		}
	} else if (option == OPTION_COM1 && request_region(COM1_ADDR, NUM_PORTS, COM1_PORT_NAME) == NULL) {
		err = -EBUSY;
		goto out_unregister;
  	} else if (option == OPTION_COM2 && request_region(COM2_ADDR, NUM_PORTS, COM2_PORT_NAME) == NULL) {
		err = -EBUSY;
		goto out_release_region;
	}

	
	if (option == OPTION_BOTH) {
		err = request_irq(IRQ_COM1, uart16550_interrupt_handle, IRQF_SHARED, COM1_PORT_NAME, &devs[0]);
		if (err != 0) {
			pr_err("request_irq failed: %d\n", err);
			goto out_release_regions;
		}

		err = request_irq(IRQ_COM2, uart16550_interrupt_handle, IRQF_SHARED, COM2_PORT_NAME, &devs[1]);
		if (err != 0) {
			pr_err("request_irq failed: %d\n", err);
			goto out_release_irq_com1;
		}
	} else if (option == OPTION_COM1) {
		err = request_irq(IRQ_COM1, uart16550_interrupt_handle, IRQF_SHARED, COM1_PORT_NAME, &devs[0]);
		if (err != 0) {
			pr_err("request_irq failed: %d\n", err);
			goto out_release_regions;
		}
	} else if (option == OPTION_COM2) {
		err = request_irq(IRQ_COM2, uart16550_interrupt_handle, IRQF_SHARED, COM2_PORT_NAME, &devs[1]);
		if (err != 0) {
			pr_err("request_irq failed: %d\n", err);
			goto out_release_irq_com1;
		}
	}

	if (option == OPTION_BOTH) {
		devs[0].device_num = COM1_DEVICE_NUM;
		devs[1].device_num = COM2_DEVICE_NUM;
	} else if (option == OPTION_COM1) {
		devs[0].device_num = COM1_DEVICE_NUM;
	} else if (option == OPTION_COM2) {
		devs[1].device_num = COM2_DEVICE_NUM;
	}

	for (int i = 0; i < num_minors; i++) {
		spin_lock_init(&devs[i].lock);
		init_waitqueue_head(&devs[i].wq_reads);
		init_waitqueue_head(&devs[i].wq_writes);
		INIT_KFIFO(devs[i].read_fifo);
		INIT_KFIFO(devs[i].write_fifo);
		cdev_init(&devs[i].cdev, &uart16550_fops);
		cdev_add(&devs[i].cdev, MKDEV(MAJOR, i), 1);
	}

	return 0;

out_release_irq_com1
	free_irq(I8042_KBD_IRQ, &devs[0]);

out_release_regions:
	release_region(I8042_STATUS_REG+1, 1);
out_release_region:
	release_region(I8042_DATA_REG+1, 1);

out_unregister:
	unregister_chrdev_region(MKDEV(MAJOR, MINOR_NUM), num_minors);
out:
	return err;
}

static void uart16550_exit(void)
{
	if (option == OPTION_BOTH) {
		cdev_del(&devs[0].cdev);
		cdev_del(&devs[1].cdev);

		free_irq(IRQ_COM1, &devs[0]);
		free_irq(IRQ_COM2, &devs[1]);

		release_region(COM1_ADDR, NUM_PORTS);
		release_region(COM2_ADDR, NUM_PORTS);

		unregister_chrdev_region(MKDEV(MAJOR, MINOR_NUM), 2);
	} else if (option == OPTION_COM1) {
		cdev_del(&devs[0].cdev);

		free_irq(IRQ_COM1, &devs[0]);

		release_region(COM1_ADDR, NUM_PORTS);

		unregister_chrdev_region(MKDEV(MAJOR, MINOR_NUM), 1);
	} else if (option == OPTION_COM2) {
		cdev_del(&devs[1].cdev);

		free_irq(IRQ_COM2, &devs[1]);

		release_region(COM2_ADDR, NUM_PORTS);

		unregister_chrdev_region(MKDEV(MAJOR, MINOR_NUM), 1);
	}

	pr_notice("Driver %s unloaded\n", MODULE_NAME);
}

module_init(uart16550_init);
module_exit(uart16550_exit);

MODULE_DESCRIPTION("UART 16550A driver");
MODULE_AUTHOR("Bogdan-Mihai Tudorache");
MODULE_LICENSE("GPL v2");
