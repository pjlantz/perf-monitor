#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/kdebug.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/ptrace.h>

#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <linux/time.h>

#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>


#include <linux/workqueue.h>
#include <linux/slab.h>

const char TAG[] = "Perf Driver :";

// Device info
static dev_t mdev;
static struct cdev c_dev;
static struct class *cl;

// logging file
struct file *f;
char filename[50];
static char *meta = "";
static char *app = "";
static char *in1 = "";
char log[100];

static struct perf_event *event1;
static struct perf_event *event2;
static struct perf_event *event3;
static struct perf_event *event4;
static struct perf_event *sampleEvent;

typedef unsigned long long int __u64;
// Sampling period
int period;
// PID of program
int pid;

// Event types
int e1;
int e2;
int e3;
int e4;
int sample; 

struct task_struct *task;
static struct workqueue_struct *my_wq;

typedef struct {
  struct work_struct my_work;
  __u64    sample;
  __u64    ev1;
  __u64    ev2;
  __u64    ev3;
  __u64    ev4;
} my_work_t;

static struct perf_event_attr wd_hw_attr_sample = { 
         .type           = PERF_TYPE_RAW,
         .config         = 0x0,
		 .size		 	 = sizeof(struct perf_event_attr),
         .sample_period  = 0,
		 .pinned 		 = 1,
         .disabled       = 1,
         .exclude_kernel = 1,
         .exclude_user   = 0,
		 .inherit 		 = 1,
};

static struct perf_event_attr wd_hw_attr_event_1 = {
         .type           = PERF_TYPE_RAW,
         .config         = 0x0,
	 	 .size		     = sizeof(struct perf_event_attr),
		 .pinned 		 = 1,
         .disabled       = 1,
         .exclude_kernel = 1,
         .exclude_user   = 0,
		 .inherit 		 = 1,
};

static struct perf_event_attr wd_hw_attr_event_2 = {
         .type           = PERF_TYPE_RAW,
         .config         = 0x0,
	 	 .size 		     = sizeof(struct perf_event_attr),
		 .pinned 		 = 1,
         .disabled       = 1,
         .exclude_kernel = 1,
         .exclude_user   = 0,
		 .inherit 		 = 1,
};

static struct perf_event_attr wd_hw_attr_event_3 = {
         .type           = PERF_TYPE_RAW,
         .config         = 0x0,
	 	 .size 		     = sizeof(struct perf_event_attr),
		 .pinned 		 = 1,
         .disabled       = 1,
         .exclude_kernel = 1,
         .exclude_user   = 0,
		 .inherit 		 = 1,
};

static struct perf_event_attr wd_hw_attr_event_4 = {
         .type           = PERF_TYPE_RAW,
         .config         = 0x0,
	 	 .size 		     = sizeof(struct perf_event_attr),
		 .pinned 		 = 1,
         .disabled       = 1,
         .exclude_kernel = 1,
         .exclude_user   = 0,
		 .inherit 		 = 1,
};


struct file* file_open(const char* path, int flags, int rights) {
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if(IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}


void file_close(struct file* file) {
    filp_close(file, NULL);
}


int file_read(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {

    int ret;
    mm_segment_t oldfs;
    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}   


int file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}


int file_sync(struct file* file) {
    vfs_fsync(file, 0);
    return 0;
}


static void my_wq_function( struct work_struct *work) {
	my_work_t *my_work = (my_work_t *)work;

	char log2[100];
	sprintf(log2, "%llu,%llu,%llu,%llu,%llu\n", my_work->sample,my_work->ev1,my_work->ev2,my_work->ev3,my_work->ev4);
	file_write(f, 0, log2, strlen(log2));
	//kfree(work);
	return;
}


static void dummy(struct perf_event *event, struct perf_sample_data *data, struct pt_regs *regs) {
    printk(KERN_NOTICE "%s Got interrupt in dummy!\n", TAG);
    if (event->state != PERF_EVENT_STATE_ACTIVE) {
        printk(KERN_NOTICE "%s dummy is NOT active\n", TAG);
    }
    if (event->state == PERF_EVENT_STATE_OFF) {
        printk(KERN_NOTICE "%s dummy state off\n", TAG);
        perf_event_enable(event);
    }
}

static void hyper_overflow_callback(struct perf_event *event, struct perf_sample_data *data, struct pt_regs *regs) {
    u64 r, e;
    if (event->state != PERF_EVENT_STATE_ACTIVE) {
        printk(KERN_NOTICE "%s Perf event is NOT active!\n", TAG);
    }

    if (event->state == PERF_EVENT_STATE_ACTIVE) {

        //local64_t sample = event->count;
		__u64 sample = perf_event_read_value(event,&r,&e);
        //u64 samplebytes = perf_event_read_value(event,&r,&e);
        __u64 ev1 = perf_event_read_value(event1,&r,&e);
        __u64 ev2 = perf_event_read_value(event2,&r,&e);
        __u64 ev3 = perf_event_read_value(event3,&r,&e);
        __u64 ev4 = perf_event_read_value(event4,&r,&e);

        my_work_t *work;
		work = (my_work_t *)kmalloc(sizeof(my_work_t), GFP_KERNEL);
		if (work) {
			INIT_WORK((struct work_struct *) work, my_wq_function);
			work->sample = sample;
			work->ev1 = ev1;
			work->ev2 = ev2;
			work->ev3 = ev3;
			work->ev4 = ev4;
			queue_work(my_wq, (struct work_struct *) work);
		} else {
        	printk(KERN_NOTICE "%s Not enough memory!\n", TAG);
		}
		local64_set(&event->count, 0);
		local64_set(&event1->count, 0);
		local64_set(&event2->count, 0);
		local64_set(&event3->count, 0);
		local64_set(&event4->count, 0);
    }
}


static int perf_open(struct inode *i, struct file *f) {
    printk(KERN_INFO "%s open()\n", TAG);
    if (sampleEvent && event1 && event1 && event2 && event3 && event4) {
        perf_event_disable(sampleEvent);
        perf_event_disable(event1);
        perf_event_disable(event2);
        perf_event_disable(event3);
        perf_event_disable(event4);
    	perf_event_release_kernel(sampleEvent);
   	 	perf_event_release_kernel(event1);
    	perf_event_release_kernel(event2);
   	 	perf_event_release_kernel(event3);
    	perf_event_release_kernel(event4);
	}
    return 0;
}


static int perf_close(struct inode *i, struct file *f) {
    printk(KERN_INFO "%s close()\n", TAG);
    return 0;
}



static ssize_t perf_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    printk(KERN_INFO "%s read()\n", TAG);
    return 0;
}


static ssize_t perf_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    printk(KERN_INFO "%s write(): %s \n", TAG, buf);
    return len;
}


static struct file_operations pugs_fops = {
    .owner = THIS_MODULE,
    .open = perf_open,
    .release = perf_close,
    .read = perf_read,
    .write = perf_write
};


static void killall(void) {

    cdev_del(&c_dev);
    device_destroy(cl, mdev);
    class_destroy(cl);
    unregister_chrdev_region(mdev, 1);
    file_close(f);
    if (my_wq) {
	    flush_workqueue(my_wq);
	    destroy_workqueue(my_wq);
    }
    if (sampleEvent && event1 && event1 && event2 && event3 && event4) {
        perf_event_disable(sampleEvent);
        perf_event_disable(event1);
        perf_event_disable(event2);
        perf_event_disable(event3);
        perf_event_disable(event4);
    	perf_event_release_kernel(sampleEvent);
   	 	perf_event_release_kernel(event1);
    	perf_event_release_kernel(event2);
   	 	perf_event_release_kernel(event3);
    	perf_event_release_kernel(event4);
	}
    printk(KERN_INFO "%s device unregistered\n", TAG);
}



int init_app(struct subprocess_info *info, struct cred *new) {
	int ppid = pid;    
	if (info != NULL && new != NULL && pid == 0)  {
		task =  pid_task(find_vpid(current->pid), PIDTYPE_PID);
    	ppid = task->pid;
	} else {
		//struct task_struct *ts;
		//task = pid_task(find_vpid(pid), PIDTYPE_PID);
		task = task->parent;
		//get_task_struct(task);
		int status;
		
		//task = ts;
	    printk(KERN_INFO "%s Second if, task comm %s state %i\n", TAG, task->comm, task->state);
	}
    printk(KERN_ERR "%s Monitoring pid: %i\n", TAG, task->pid);
	if (task == NULL) {
		killall();
		return 0;
	}

	struct timeval now;
	unsigned int temp;
	do_gettimeofday(&now);
	temp = now.tv_sec;
    sprintf(filename, "/tmp/perf-%i-%i-[%s].log", ppid, temp, meta);
    f = file_open(filename, O_CREAT | O_WRONLY | O_APPEND, 0);
    if (f == NULL) {
    	printk(KERN_ERR "%s Error opening file %s\n", TAG, filename); 
    }
    file_write(f, 0, log, strlen(log));

    my_wq = create_workqueue("my_queue");
	struct perf_event_attr *wd_attr_sample = &wd_hw_attr_sample;
	struct perf_event_attr *wd_attr_event_1 = &wd_hw_attr_event_1;
	struct perf_event_attr *wd_attr_event_2 = &wd_hw_attr_event_2;
	struct perf_event_attr *wd_attr_event_3 = &wd_hw_attr_event_3;
	struct perf_event_attr *wd_attr_event_4 = &wd_hw_attr_event_4;

    sampleEvent = perf_event_create_kernel_counter(wd_attr_sample, -1, task, hyper_overflow_callback, NULL);
    event1 = perf_event_create_kernel_counter(wd_attr_event_1, -1, task, dummy, NULL);
    event2 = perf_event_create_kernel_counter(wd_attr_event_2, -1, task, dummy, NULL);
    event3 = perf_event_create_kernel_counter(wd_attr_event_3, -1, task, dummy, NULL);
    event4 = perf_event_create_kernel_counter(wd_attr_event_4, -1, task, dummy, NULL);

    printk(KERN_ERR "%s created kernel counter(s)\n", TAG);
    printk(KERN_INFO "%s initialization successful\n", TAG);

    perf_event_enable(sampleEvent);
    perf_event_enable(event1);
    perf_event_enable(event2);
    perf_event_enable(event3);
    perf_event_enable(event4);

    return 0;
}


/* Constructor */
static int __init perf_init(void) {
    if(alloc_chrdev_region(&mdev, 0, 1, "perf") < 0) {
        return -1;
    }

    printk(KERN_INFO "%s device <%d,%d> registered\n", TAG, MAJOR(mdev), MINOR(mdev));

    if((cl = class_create(THIS_MODULE, "perf")) == NULL) {
        printk(KERN_ERR "%s could not create class!\n", TAG);
        unregister_chrdev_region(mdev, 1);
        return -1;
    }
    if(device_create(cl, NULL, mdev, NULL, "perf") == NULL) {
        printk(KERN_ERR "%s could not create device!\n", TAG);
        class_destroy(cl);
        unregister_chrdev_region(mdev, 1);
        return -1;
    }
    cdev_init(&c_dev, &pugs_fops);
    if(cdev_add(&c_dev, mdev, 1) == -1) {
        printk(KERN_ERR "%s could not add device!\n", TAG);
        device_destroy(cl, mdev);
        class_destroy(cl);
        unregister_chrdev_region(mdev, 1);
        return -1;
    }

	wd_hw_attr_sample.config = (int) sample;
    wd_hw_attr_sample.sample_period = (int) period;

    wd_hw_attr_event_1.config = (int) e1;
    wd_hw_attr_event_2.config = (int) e2;
    wd_hw_attr_event_3.config = (int) e3;
    wd_hw_attr_event_4.config = (int) e4;

    sprintf(log, "0x%06lx,0x%06lx,0x%06lx,0x%06lx,0x%06lx\n", (int) wd_hw_attr_sample.config, (int) wd_hw_attr_event_1.config, (int) wd_hw_attr_event_2.config, (int) wd_hw_attr_event_3.config, (int) wd_hw_attr_event_4.config); 

    if (pid == 0) {
		struct subprocess_info *sub_info;
		char *argv[] = {app, in1, NULL};
		static char *envp[] = {
			"HOME=/",
			"TERM=linux",
			"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

		printk(KERN_ERR "%s current pid %i\n", TAG, current->pid);
		sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_ATOMIC, &init_app, NULL, NULL);
		//sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_ATOMIC);

		if (sub_info == NULL) printk(KERN_ERR "%s sub_info  is NULL\n", TAG);
		printk(KERN_ERR "%s usermodehelper exec\n", TAG);
		call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
		//killall();
	} else {
		printk(KERN_ERR "%s init app\n", TAG);
		init_app(NULL, NULL);
	}
    return 0;
}


/* Destructor */
static void __exit perf_exit(void) {
    killall();
}

 
module_init(perf_init);
module_exit(perf_exit);
 
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("perf counter driver");

module_param(pid, int, 0);
MODULE_PARM_DESC(pid, "PID of existing process to monitor");

module_param(app, charp, 0000);
MODULE_PARM_DESC(app, "Path to binary to monitor");

module_param(in1, charp, 0000);
MODULE_PARM_DESC(in1, "1st input parameter to app");

module_param(period, int, 0);
MODULE_PARM_DESC(period, "Sampling period");

module_param(sample, int, 0);
MODULE_PARM_DESC(sample, "Event type to sample on");

module_param(e1, int, 0);
MODULE_PARM_DESC(e1, "Type of event for counter #1");

module_param(e2, int, 0);
MODULE_PARM_DESC(e2, "Type of event for counter #2");

module_param(e3, int, 0);
MODULE_PARM_DESC(e3, "Type of event for counter #3");

module_param(e4, int, 0);
MODULE_PARM_DESC(e4, "Type of event for counter #4");

module_param(meta, charp, 0000);
MODULE_PARM_DESC(meta, "Description of monitoring");

