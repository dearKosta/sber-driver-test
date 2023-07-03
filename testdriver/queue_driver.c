#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/mutex.h>

#define DEVICE_NAME "queue_device"
#define QUEUE_SIZE 1000

struct queue_node {
    struct list_head list;
    char data;
};

struct queue_device_data {
    struct list_head queue;
    int size;
};

struct queue_device {
    struct queue_device_data data; //default queue
    struct queue_device_data queues; //parallel queues
    mutex_t data_lock;
    mutex_t queues_lock;
};

static struct cdev cdev;
static dev_t dev;
static struct queue_device *device;

void init_queue(struct queue_device_data *queue);
void init_device(struct queue_device *device);
int create_parallel_queue(struct queue_device_data *queues, struct file *filp);
struct queue_device_data* get_device_queue(struct queue_device *device, struct file *filp);
void destroy_queue(struct queue_device_data *data);

static inline void destroy_queue(struct queue_device_data *data)
{
    struct queue_node *node, *tmp;

    list_for_each_entry_safe(node, tmp, &data->queue, list) {
        list_del(&node->list);
        kfree(node);
    }
}

static inline void init_queue(struct queue_device_data *data)
{
    INIT_LIST_HEAD(&data->queue);
    data->size = 0;
}

static inline int create_parallel_queue(struct queue_device_data *queues, struct file *filp)
{
    struct queue_device_data *node;

    node = kmalloc(sizeof(struct queue_device_data), GFP_KERNEL);
    if (!node)
        return -ENOMEM;;
    
    init_queue(node);

    list_add_tail(&node->queue, &queues->queue);
    queues->size++;
    filp->private_data =  node; //save data queue for parallel processing

    return 0;
}

static inline void init_device (struct queue_device *device)
{
    mutex_init(&device->data_lock);
    mutex_init(&device->queues_lock);
    init_queue(&device->data);
    init_queue(&device->queues);
}

static inline struct queue_device_data* get_device_queue(struct queue_device *device, struct file *filp)
{
    if (filp->f_flags & O_NONBLOCK) {
        if (list_empty(&device->queues.queue))
            return NULL;
    
        return filp->private_data;
    }

    return &device->data;
}

static int queue_open(struct inode *inode, struct file *filp)
{
    int result = 0;

    //Exclusive access
    if (filp->f_flags & O_EXCL) {
        if (!mutex_trylock(&device->data_lock)) {
            pr_err("Device is blocked. Cannot open device exclusively.n");
            return -EBUSY;
        }

        return 0;
    }

    if (filp->f_flags & O_NONBLOCK) {
        mutex_lock(&device->queues_lock);
        result = create_parallel_queue(&device->queues, filp);
        mutex_unlock(&device->queues_lock);

        return result;
    }

    //default mode without any checks
    return 0;
}

static int queue_release(struct inode *inode, struct file *filp)
{
    if (filp->f_flags & O_EXCL) {
        mutex_unlock(&device->data_lock);
    }

    return 0;
}

static ssize_t queue_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    struct queue_node *node;
    struct queue_device_data  *data_queue;
    ssize_t bytes_read = 0;

    data_queue = get_device_queue(device, filp);

    if (NULL == data_queue)
        return -EFAULT;

    node = list_first_entry(&data_queue->queue, struct queue_node, list);
    list_del(&node->list);
    data_queue->size--;

    if (copy_to_user(buf, &node->data, sizeof(char))) {
        kfree(node);
        return -EFAULT;
    }

    kfree(node);
    bytes_read = sizeof(char);

    return bytes_read;
}

static ssize_t queue_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    struct queue_node *node;
    struct queue_device_data  *data_queue;

    if (filp->f_flags & O_NONBLOCK)
         data_queue = get_device_queue(filp); 
    else 
         data_queue = &device->data;

    if (NULL == data_queue)
        return -EFAULT;

    if (data_queue->size >= QUEUE_SIZE)
        return -ENOSPC;

    node = kmalloc(sizeof(struct queue_node), GFP_KERNEL);
    if (!node)
        return -ENOMEM;

    if (copy_from_user(&node->data, buf, sizeof(char))) {
        kfree(node);
        return -EFAULT;
    }

    list_add_tail(&node->list, &data_queue->queue);
    data_queue->size++;

    return sizeof(char);
}

static const struct file_operations queue_fops = {
    .owner = THIS_MODULE,
    .open = queue_open,
    .release = queue_release,
    .read = queue_read,
    .write = queue_write,
};

static int __init queue_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("Failed to allocate device number.n");
        return ret;
    }

    cdev_init(&cdev, &queue_fops);
    cdev.owner = THIS_MODULE;

    ret = cdev_add(&cdev, dev, 1);
    if (ret < 0) {
        pr_err("Failed to add character device.n");
        unregister_chrdev_region(dev, 1);
        return ret;
    }

    device = kmalloc(sizeof(struct queue_device), GFP_KERNEL);
    if (!device) {
        pr_err("Failed to allocate device data.n");
        cdev_del(&cdev);
        unregister_chrdev_region(dev, 1);
        return -ENOMEM;
    }
    
    init_device(device);

    pr_info("Queue device initialized.n");

    return 0;
}

static void __exit queue_exit(void)
{
    struct queue_device_data *node, *tmp;

    destroy_queue(device->data);
    
    list_for_each_entry_safe(node, tmp, &device->queues.queue, list) {
        destroy_queue(node); //destroy symbol data queue nodes
        list_del(&node->queue); //delete queue
        kfree(node);
    }

    kfree(device);

    cdev_del(&cdev);
    unregister_chrdev_region(dev, 1);

    pr_info("Queue device exited.n");
}

module_init(queue_init);
module_exit(queue_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Puzakov Konstantin");
MODULE_DESCRIPTION("Queue Device Driver");