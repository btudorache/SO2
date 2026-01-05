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
#include <linux/moduleparam.h>

#include "uart16550.h"

#define MODULE_NAME     "uart16550"
#define COM1_ADDR      0x3f8
#define COM2_ADDR      0x2f8
#define PORT_SIZE      8

#define IRQ_COM1       4
#define IRQ_COM2       3

/* Register offsets */
#define REG_RBR     0   /* Receive Buffer Register (read) */
#define REG_THR     0   /* Transmitter Holding Register (write) */
#define REG_DLL     0   /* Divisor Latch LSB */
#define REG_DLM     1   /* Divisor Latch MSB */
#define REG_IER     1   /* Interrupt Enable Register */
#define REG_IIR     2   /* Interrupt Identification Register */
#define REG_FCR     2   /* FIFO Control Register */
#define REG_LCR     3   /* Line Control Register */
#define REG_MCR     4   /* Modem Control Register */
#define REG_LSR     5   /* Line Status Register */
#define REG_MSR     6   /* Modem Status Register */

/* Status register bits */
#define LSR_DR      0x01    /* Data Ready */
#define LSR_THRE    0x20    /* Transmitter Holding Register Empty */

#define FIFO_SIZE   512

/* Module parameters */
static int major = 42;
static int option = OPTION_BOTH;

module_param(major, int, 0644);
MODULE_PARM_DESC(major, "Major number (default=42)");
module_param(option, int, 0644);
MODULE_PARM_DESC(option, "Port option: 1=COM1, 2=COM2, 3=both (default=3)");

struct uart_port {
    unsigned int            iobase;
    int                    irq;
    spinlock_t             lock;
    DECLARE_KFIFO(rxfifo, unsigned char, FIFO_SIZE);
    DECLARE_KFIFO(txfifo, unsigned char, FIFO_SIZE);
    wait_queue_head_t      rxwait;
    wait_queue_head_t      txwait;
    struct cdev            cdev;
};

static struct uart_port ports[2];

/* Hardware access functions */
static inline unsigned char io_read(struct uart_port *port, int reg)
{
    return inb(port->iobase + reg);
}

static inline void io_write(struct uart_port *port, int reg, unsigned char value)
{
    outb(value, port->iobase + reg);
}

/* Initialize UART hardware */
static void hw_init(struct uart_port *port)
{
    unsigned long flags;

    spin_lock_irqsave(&port->lock, flags);

    /* Disable all interrupts */
    io_write(port, REG_IER, 0);

    /* Enable and clear FIFOs */
    io_write(port, REG_FCR, 0x07);

    /* 8N1 mode */
    io_write(port, REG_LCR, 0x03);

    /* Enable OUT2 (required for interrupts) */
    io_write(port, REG_MCR, 0x08);

    /* Set baud rate to 9600 */
    io_write(port, REG_LCR, io_read(port, REG_LCR) | 0x80);  /* Set DLAB */
    io_write(port, REG_DLL, 12);  /* 115200/9600 = 12 */
    io_write(port, REG_DLM, 0);
    io_write(port, REG_LCR, io_read(port, REG_LCR) & ~0x80); /* Clear DLAB */

    /* Enable RX and TX interrupts */
    io_write(port, REG_IER, 0x03);

    spin_unlock_irqrestore(&port->lock, flags);
}

static irqreturn_t uart_interrupt(int irq, void *dev_id)
{
    struct uart_port *port = dev_id;
    unsigned char iir;
    char ch;
    unsigned long flags;
    int handled = 0;

    spin_lock_irqsave(&port->lock, flags);

    /* Loop to handle all pending interrupts */
    while (1) {
        iir = io_read(port, REG_IIR);

        /* Bit 0 = 1 means no interrupt pending */
        if (iir & 0x01)
            break;

        handled = 1;

        switch (iir & 0x0e) {
        case 0x04: /* Received data available */
        case 0x0c: /* Character timeout */
            while (io_read(port, REG_LSR) & LSR_DR) {
                ch = io_read(port, REG_RBR);
                kfifo_in(&port->rxfifo, &ch, 1);
            }
            wake_up_interruptible(&port->rxwait);
            break;

        case 0x02: /* Transmitter holding register empty */
            while ((io_read(port, REG_LSR) & LSR_THRE) &&
                   kfifo_out(&port->txfifo, &ch, 1)) {
                io_write(port, REG_THR, ch);
            }
            wake_up_interruptible(&port->txwait);
            break;
        }
    }

    spin_unlock_irqrestore(&port->lock, flags);
    return handled ? IRQ_HANDLED : IRQ_NONE;
}

static int uart_open(struct inode *inode, struct file *file)
{
    struct uart_port *port = container_of(inode->i_cdev, struct uart_port, cdev);
    file->private_data = port;
    return 0;
}

static int uart_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t uart_read(struct file *file, char __user *buf,
                       size_t count, loff_t *ppos)
{
    struct uart_port *port = file->private_data;
    unsigned int copied;

    if (wait_event_interruptible(port->rxwait,
                kfifo_len(&port->rxfifo) > 0))
        return -ERESTARTSYS;

    if (kfifo_to_user(&port->rxfifo, buf, count, &copied))
        return -EFAULT;

    return copied;
}

static ssize_t uart_write(struct file *file, const char __user *buf,
                        size_t count, loff_t *ppos)
{
    struct uart_port *port = file->private_data;
    unsigned int copied;
    unsigned long flags;
    char ch;

    if (kfifo_from_user(&port->txfifo, buf, count, &copied))
        return -EFAULT;

    /* Start transmission if TX empty */
    spin_lock_irqsave(&port->lock, flags);
    while ((io_read(port, REG_LSR) & LSR_THRE) &&
           kfifo_out(&port->txfifo, &ch, 1)) {
        io_write(port, REG_THR, ch);
    }
    spin_unlock_irqrestore(&port->lock, flags);

    return copied;
}

static long uart_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct uart_port *port = file->private_data;
    struct uart16550_line_info line;
    unsigned long flags;

    if (cmd != UART16550_IOCTL_SET_LINE)
        return -ENOTTY;

    if (copy_from_user(&line, (void __user *)arg, sizeof(line)))
        return -EFAULT;

    spin_lock_irqsave(&port->lock, flags);

    /* Set DLAB and configure baud rate */
    io_write(port, REG_LCR, io_read(port, REG_LCR) | 0x80);
    io_write(port, REG_DLL, line.baud & 0xff);
    io_write(port, REG_DLM, (line.baud >> 8) & 0xff);

    /* Configure line parameters and clear DLAB */
    io_write(port, REG_LCR, (line.len & 0x03) |
                          ((line.stop & 0x01) << 2) |
                          (line.par & 0x38));

    spin_unlock_irqrestore(&port->lock, flags);
    return 0;
}

static const struct file_operations uart_fops = {
    .owner          = THIS_MODULE,
    .open           = uart_open,
    .release        = uart_release,
    .read           = uart_read,
    .write          = uart_write,
    .unlocked_ioctl = uart_ioctl,
};

static int init_port(struct uart_port *port, int minor)
{
    int ret;

    spin_lock_init(&port->lock);
    init_waitqueue_head(&port->rxwait);
    init_waitqueue_head(&port->txwait);
    INIT_KFIFO(port->rxfifo);
    INIT_KFIFO(port->txfifo);

    /* Request I/O region before doing anything else */
    if (!request_region(port->iobase, PORT_SIZE, MODULE_NAME)) {
        pr_err("uart16550: cannot get IO region %x\n", port->iobase);
        ret = -EBUSY;
        goto fail_io;
    }

    /* Request IRQ next */
    ret = request_irq(port->irq, uart_interrupt, IRQF_SHARED,
                     MODULE_NAME, port);
    if (ret) {
        pr_err("uart16550: cannot get IRQ %d\n", port->irq);
        goto fail_irq;
    }

    /* Register character device */
    cdev_init(&port->cdev, &uart_fops);
    port->cdev.owner = THIS_MODULE;
    ret = cdev_add(&port->cdev, MKDEV(major, minor), 1);
    if (ret) {
        pr_err("uart16550: cannot add character device\n");
        goto fail_cdev;
    }

    /* Initialize hardware last */
    hw_init(port);

    return 0;

fail_cdev:
    free_irq(port->irq, port);
fail_irq:
    release_region(port->iobase, PORT_SIZE);
fail_io:
    return ret;
}

static void cleanup_port(struct uart_port *port)
{
    cdev_del(&port->cdev);
    free_irq(port->irq, port);
    release_region(port->iobase, PORT_SIZE);
}

static int __init uart16550_init(void)
{
    int ret;
    int num_devices = 0;  /* Number of devices to register */
    int first_minor = 0;  /* First minor number */

    /* Validate option parameter */
    if (option != OPTION_COM1 && option != OPTION_COM2 && option != OPTION_BOTH) {
        pr_err("uart16550: invalid option parameter (must be 1, 2, or 3)\n");
        return -EINVAL;
    }

    /* Determine the number of devices and first minor number based on the option */
    if (option == OPTION_BOTH) {
        num_devices = 2;  /* Register both COM1 and COM2 */
        first_minor = 0;  /* Minors 0 and 1 */
    } else if (option == OPTION_COM1) {
        num_devices = 1;  /* Register only COM1 */
        first_minor = 0;  /* Minor 0 */
    } else if (option == OPTION_COM2) {
        num_devices = 1;  /* Register only COM2 */
        first_minor = 1;  /* Minor 1 */
    }

    /* Register character device region */
    ret = register_chrdev_region(MKDEV(major, first_minor), num_devices, MODULE_NAME);
    if (ret < 0) {
        pr_err("uart16550: cannot register char device region\n");
        return ret;
    }

    /* Initialize requested ports */
    if (option == OPTION_COM1 || option == OPTION_BOTH) {
        ports[0].iobase = COM1_ADDR;
        ports[0].irq = IRQ_COM1;
        ret = init_port(&ports[0], first_minor);
        if (ret)
            goto fail_init;
    }

    if (option == OPTION_COM2 || option == OPTION_BOTH) {
        ports[1].iobase = COM2_ADDR;
        ports[1].irq = IRQ_COM2;
        ret = init_port(&ports[1], (option == OPTION_BOTH) ? (first_minor + 1) : first_minor);
        if (ret) {
            if (option == OPTION_BOTH)
                cleanup_port(&ports[0]);
            goto fail_init;
        }
    }

    pr_info("uart16550: initialized with major=%d, option=%d\n",
            major, option);
    return 0;

fail_init:
    unregister_chrdev_region(MKDEV(major, first_minor), num_devices);
    return ret;
}

static void __exit uart16550_exit(void)
{
    int num_devices = 0;  /* Number of devices to unregister */
    int first_minor = 0;  /* First minor number */

    /* Determine the number of devices and first minor number based on the option */
    if (option == OPTION_BOTH) {
        num_devices = 2;  /* Unregister both COM1 and COM2 */
        first_minor = 0;  /* Minors 0 and 1 */
    } else if (option == OPTION_COM1) {
        num_devices = 1;  /* Unregister only COM1 */
        first_minor = 0;  /* Minor 0 */
    } else if (option == OPTION_COM2) {
        num_devices = 1;  /* Unregister only COM2 */
        first_minor = 1;  /* Minor 1 */
    }

    /* Clean up requested ports */
    if (option == OPTION_COM2 || option == OPTION_BOTH)
        cleanup_port(&ports[1]);
    if (option == OPTION_COM1 || option == OPTION_BOTH)
        cleanup_port(&ports[0]);

    /* Unregister character device region */
    unregister_chrdev_region(MKDEV(major, first_minor), num_devices);
    pr_info("uart16550: cleaned up\n");
}

module_init(uart16550_init);
module_exit(uart16550_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tudorache Bogdan");
MODULE_DESCRIPTION("16550 UART Driver");