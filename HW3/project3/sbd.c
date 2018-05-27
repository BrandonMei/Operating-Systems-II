/*
 * A sample, extra-simple block driver. Updated for kernel 2.6.31.
 *
 * (C) 2003 Eklektix, Inc.
 * (C) 2010 Pat Patterson <pat at superpat dot com>
 * Redistributable under the terms of the GNU GPL.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>

#include <linux/slab.h>	  /* kmmalloc */
#include <linux/fcntl.h>  /* File I/O */
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/kdev_t.h>
#include <linux/buffer_head.h>
#include <linux/bio.h>
#include <linux/crypto.h> /*encryption lib */
#include <linux/scatterlist.h>

MODULE_LICENSE("Dual BSD/GPL");
static char *Version = "1.4";

static int major_num = 0;
module_param(major_num, int, 0);

static int logical_block_size = 512;
module_param(logical_block_size, int, 0);

static int nsectors = 1024; /* How big the drive is */
module_param(nsectors, int, 0);

/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE 512

/*
 * Our request queue.
 */
static struct request_queue *Queue;

/*
 * The internal representation of our device data.
 */
static struct sbd_device {
	unsigned long size;    /* the device size in sectors */
	spinlock_t lock;       /* mutex */
	u8 *data;              /* data array */
	struct gendisk *gd;
} Device;

  struct crypto_cipher *tfm;
  static char *key = "0123456789123456";
  module_param(key, charp, 0644);
  static int keylen = 16;
  module_param(keylen, int, 0644);

/*
 * Handle an I/O request.
 */
static void sbd_transfer(struct sbd_device *dev, sector_t sector,
		unsigned long nsect, char *buffer, int write) {
	unsigned long offset = sector * logical_block_size;
	unsigned long nbytes = nsect * logical_block_size;
	u8 *destination;
	u8 *source;

	if (write)
		printk("sbd.c: sbd_transfer().....Write transfer\n");
	else
		printk("sbd.c: sbd_transfer().....Read transfer\n");

	if ((offset + nbytes) > dev->size) {
		printk ("sbd.c: sbd_transfer().....offset is beyond: %1d Nbytes: %ld\n", offset, nbytes);
		return;
	}

	if (crypto_cipher_setkey(tfm, key, keylen) == 0) {
		printk("sbd.c: sbd_transfer().....key is set and encrypted\n");
	} else {
		printk("sbd.c: sbd_transfer().....key didn't set\n");
	}

	int i;
	if (write) {
		printk("[ sbd.c: sbd_transfer() ] - Write %lu bytes to device data\n", nbytes);
		destination = dev->data + offset;
		source = buffer;

    /* going through crypto cipher and tfm to decrypt data */
		for (i = 0; i < nbytes; i += crypto_cipher_blocksize(tfm)) {
			crypto_cipher_encrypt_one(
					tfm,
					dev->data + offset + i,
					buffer + i
					);
		}

		printk("sbd.c: sbd_transfer().....Decryption Data:\n");
		for (i = 0; i < 100; i++) {
			printk("%u", (unsigned) *destination++);
		}

		printk("\nsbd.c: sbd_transfer().....Encrypted Data:\n");
		for (i = 0; i < 100; i++) {
			printk("%u", (unsigned) *source++);
		}
		printk("\n");
	}
	else {
		printk("sbd.c: sbd_transfer().....Reading %lu bytes\n", nbytes);
		destination = dev->data + offset;
		source = buffer;

		for (i = 0; i < nbytes; i += crypto_cipher_blocksize(tfm)) {
			crypto_cipher_decrypt_one(
					tfm,
					buffer + i,
					dev->data + offset + i
					);
		}

		printk("sbd.c: sbd_transfer().....Decryption Data:\n");
		for (i = 0; i < 100; i++) {
			printk("%u", (unsigned) *destination++);
		}

		printk("\nsbd.c: sbd_transfer().....Encrypted Data:\n");
		for (i = 0; i < 100; i++) {
			printk("%u", (unsigned) *source++);
		}
		printk("\n");
	}
	printk("sbd.c: sbd_transfer().....Transfer done!\n");
}

static void sbd_request(struct request_queue *q) {
	struct request *req;

	req = blk_fetch_request(q); /* getting request from the top of the queue */
  printk("sbd.c: sbd_request().....Fetch Requests\n");

	while (req != NULL) {
		// blk_fs_request() was removed in 2.6.36 - many thanks to
		// Christian Paro for the heads up and fix...
		//if (!blk_fs_request(req)) {
		if (req == NULL || (req->cmd_type != REQ_TYPE_FS)) {
			printk ("sbd.c: sbd_request().....Skip non-CMD request\n");
			__blk_end_request_all(req, -EIO);
			continue;
		}

		sbd_transfer(&Device,
          blk_rq_pos(req),
          blk_rq_cur_sectors(req),
				  req->buffer,
          rq_data_dir(req));

		if ( ! __blk_end_request_cur(req, 0) ) {
			req = blk_fetch_request(q);
		}
			printk("sbd.c: sbd_transfer()......Requests done!\n");
	}
}

/*
 * The HDIO_GETGEO ioctl is handled in blkdev_ioctl(), which
 * calls this. We need to implement getgeo, since we can't
 * use tools such as fdisk to partition the drive otherwise.
 */
int sbd_getgeo(struct block_device * block_device, struct hd_geometry * geo) {
	long size;

	printk("sbd.c: sbd_getgeo()......Start Partitioning\n");

	/* We have no real geometry, of course, so make something up. */
	size = Device.size * (logical_block_size / KERNEL_SECTOR_SIZE);
	geo->cylinders = (size & ~0x3f) >> 6;
	geo->heads = 4;
	geo->sectors = 16;
	geo->start = 0;

	printk("sbd.c: sbd_getgeo().....Partition Finished\n");

  return 0;
}

/*
 * The device operations structure.
 */
static struct block_device_operations sbd_ops = {
		.owner  = THIS_MODULE,
		.getgeo = sbd_getgeo
};

static int __init sbd_init(void) {

		printk("sbd.c: sbd_init().....Start Initializing\n");

	/*
	 * Set up our internal device.
	 */
	Device.size = nsectors * logical_block_size;
	spin_lock_init(&Device.lock);
	Device.data = vmalloc(Device.size);
	if (Device.data == NULL)
		return -ENOMEM;

	/*
	 * Get a request queue.
	 */
	Queue = blk_init_queue(sbd_request, &Device.lock);
	if (Queue == NULL)
		goto out;
	blk_queue_logical_block_size(Queue, logical_block_size);

	/*
	 * Get registered.
	 */
	major_num = register_blkdev(major_num, "sbd");
	if (major_num < 0) {
		printk("[sbd.c: sbd_init().....unable to get major number\n");
		goto out;
	}

  /* allocate chiper and initialize cypto key and set key*/
	tfm = crypto_alloc_cipher("aes", 0, 0);
	if (IS_ERR(tfm))
		printk("sbd.c: sbd_init()....Error allocating Cipher\n");
	else
		printk("sbd.c: sbd_init().....Allocate Cipher\n");

	printk("sbd.c: sbd_init().....Crypto Key: %s\n", key);
	printk("sbd.c: sbd_init().....Key Length: %d\n", keylen);

	/*
	 * And the gendisk structure.
	 */
	Device.gd = alloc_disk(16);
	if (!Device.gd)
		goto out_unregister;
	Device.gd->major = major_num;
	Device.gd->first_minor = 0;
	Device.gd->fops = &sbd_ops;
	Device.gd->private_data = &Device;
	strcpy(Device.gd->disk_name, "sbd0");
	set_capacity(Device.gd, nsectors);
	Device.gd->queue = Queue;
	/* add register partition in device.gd with the kernel */
	add_disk(Device.gd);

	printk("sbd.c: sbd_init().....Initialized Blocked device.\n");

	return 0;

out_unregister:
	unregister_blkdev(major_num, "sbd");
out:
	vfree(Device.data);
	return -ENOMEM;
}

static void __exit sbd_exit(void) {
	struct file *filp = NULL;
	unsigned long long offset = 0;
	mm_segment_t fs;
	ssize_t size;
	fs = get_fs();
	set_fs(get_ds());
	filp = filp_open("/Data", O_WRONLY | O_TRUNC | O_CREAT, S_IRWXUGO);

	if (IS_ERR(filp)) {
		printk("sbd.c: sbd_exit().....Unable to Open File\n");
		set_fs(fs);
	} else {
		printk("sbd.c: sbd_exit().....File Opened\n");

		size = vfs_write(filp, Device.data, Device.size, &offset); /* writing bytes on file*/
		printk("sbd.c: sbd_exit()....Write to file: %d Offset: %llu.\n", size, offset);

		set_fs(fs); /* close the file */
		filp_close(filp, 0);
	}
	del_gendisk(Device.gd);
	put_disk(Device.gd);
	unregister_blkdev(major_num, "sbd");
	blk_cleanup_queue(Queue);
	vfree(Device.data);

	crypto_free_cipher(tfm);
	printk("sbd.c: sbd_exit().....freed crypto\n");
}

module_init(sbd_init);
module_exit(sbd_exit);

MODULE_AUTHOR("Brandon Mei, Brian Huang");
MODULE_DESCRIPTION("Block Device Driver");
