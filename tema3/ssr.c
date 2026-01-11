/*
 * Simple Software RAID - RAID-1 with CRC
 * Uses bio cloning for fast data I/O, per-sector CRC computation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/crc32.h>
#include <linux/workqueue.h>
#include <linux/slab.h>

#include "ssr.h"

MODULE_LICENSE("GPL");

#define CRC_SIZE 4
#define CRCS_PER_SECTOR (KERNEL_SECTOR_SIZE / CRC_SIZE)

static struct block_device *disk1, *disk2;
static struct gendisk *gd;
static struct request_queue *q;
static struct workqueue_struct *wq;

struct ssr_work {
	struct work_struct work;
	struct bio *bio;
};

static int ssr_open(struct block_device *b, fmode_t m) { return 0; }
static void ssr_release(struct gendisk *g, fmode_t m) { }

static const struct block_device_operations fops = {
	.owner = THIS_MODULE,
	.open = ssr_open,
	.release = ssr_release,
};

/* Sync I/O for single sector (used only for CRC sectors) */
static int sector_io(struct block_device *bd, sector_t sec, void *buf, int wr)
{
	struct bio *bio;
	struct page *pg;
	int ret;

	pg = alloc_page(GFP_NOIO);
	if (!pg)
		return -ENOMEM;

	if (wr)
		memcpy(page_address(pg), buf, KERNEL_SECTOR_SIZE);

	bio = bio_alloc(GFP_NOIO, 1);
	if (!bio) {
		__free_page(pg);
		return -ENOMEM;
	}

	bio_set_dev(bio, bd);
	bio->bi_iter.bi_sector = sec;
	bio->bi_opf = wr ? REQ_OP_WRITE : REQ_OP_READ;
	bio_add_page(bio, pg, KERNEL_SECTOR_SIZE, 0);

	ret = submit_bio_wait(bio);
	bio_put(bio);

	if (!ret && !wr)
		memcpy(buf, page_address(pg), KERNEL_SECTOR_SIZE);

	__free_page(pg);
	return ret;
}

/* Clone and submit bio to disk, wait for completion */
static int submit_clone(struct bio *bio, struct block_device *bd)
{
	struct bio *clone = bio_clone_fast(bio, GFP_NOIO, NULL);
	int ret;

	if (!clone)
		return -ENOMEM;

	bio_set_dev(clone, bd);
	ret = submit_bio_wait(clone);
	bio_put(clone);
	return ret;
}

/* CRC location helpers */
static inline sector_t crc_sector(sector_t ds)
{
	return LOGICAL_DISK_SECTORS + ds / CRCS_PER_SECTOR;
}

static inline int crc_offset(sector_t ds)
{
	return (ds % CRCS_PER_SECTOR) * CRC_SIZE;
}

/* Write CRCs for a range of data sectors to both disks */
static void write_crcs(sector_t start, struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	sector_t sec = start;
	sector_t last_crc_sec = (sector_t)-1;
	char *crc_buf = NULL;

	crc_buf = kmalloc(KERNEL_SECTOR_SIZE, GFP_NOIO);
	if (!crc_buf)
		return;

	bio_for_each_segment(bv, bio, iter) {
		char *data = kmap(bv.bv_page) + bv.bv_offset;
		unsigned int i;

		for (i = 0; i < bv.bv_len; i += KERNEL_SECTOR_SIZE, sec++) {
			sector_t cs = crc_sector(sec);
			u32 crc = crc32(0, data + i, KERNEL_SECTOR_SIZE);

			/* Load CRC sector if needed */
			if (cs != last_crc_sec) {
				/* Flush previous */
				if (last_crc_sec != (sector_t)-1) {
					sector_io(disk1, last_crc_sec, crc_buf, 1);
					sector_io(disk2, last_crc_sec, crc_buf, 1);
				}
				/* Load new */
				sector_io(disk1, cs, crc_buf, 0);
				last_crc_sec = cs;
			}

			memcpy(crc_buf + crc_offset(sec), &crc, CRC_SIZE);
		}
		kunmap(bv.bv_page);
	}

	/* Flush last CRC sector */
	if (last_crc_sec != (sector_t)-1) {
		sector_io(disk1, last_crc_sec, crc_buf, 1);
		sector_io(disk2, last_crc_sec, crc_buf, 1);
	}

	kfree(crc_buf);
}

/* Verify CRCs and return 1 if all OK, 0 if any failed */
static int verify_crcs(struct block_device *bd, sector_t start, struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	sector_t sec = start;
	sector_t last_crc_sec = (sector_t)-1;
	char *crc_buf;
	int ok = 1;

	crc_buf = kmalloc(KERNEL_SECTOR_SIZE, GFP_NOIO);
	if (!crc_buf)
		return 0;

	bio_for_each_segment(bv, bio, iter) {
		char *data = kmap(bv.bv_page) + bv.bv_offset;
		unsigned int i;

		for (i = 0; i < bv.bv_len; i += KERNEL_SECTOR_SIZE, sec++) {
			sector_t cs = crc_sector(sec);
			u32 stored, computed;

			if (cs != last_crc_sec) {
				sector_io(bd, cs, crc_buf, 0);
				last_crc_sec = cs;
			}

			memcpy(&stored, crc_buf + crc_offset(sec), CRC_SIZE);
			computed = crc32(0, data + i, KERNEL_SECTOR_SIZE);

			if (stored != computed) {
				ok = 0;
				break;
			}
		}
		kunmap(bv.bv_page);
		if (!ok)
			break;
	}

	kfree(crc_buf);
	return ok;
}

/* Handle write request */
static void do_write(struct bio *bio)
{
	sector_t start = bio->bi_iter.bi_sector;

	/* Write data to both disks */
	submit_clone(bio, disk1);
	submit_clone(bio, disk2);

	/* Write CRCs */
	write_crcs(start, bio);

	bio_endio(bio);
}

/* Handle read request */
static void do_read(struct bio *bio)
{
	sector_t start = bio->bi_iter.bi_sector;
	int d1_ok, d2_ok;

	/* Try disk1 */
	if (submit_clone(bio, disk1) == 0) {
		d1_ok = verify_crcs(disk1, start, bio);
		if (d1_ok) {
			/* Disk1 good, check if disk2 needs recovery */
			bio_endio(bio);
			return;
		}
	} else {
		d1_ok = 0;
	}

	/* Disk1 failed CRC, try disk2 */
	if (submit_clone(bio, disk2) == 0) {
		d2_ok = verify_crcs(disk2, start, bio);
		if (d2_ok) {
			/* Disk2 good - recover disk1 */
			submit_clone(bio, disk1);
			write_crcs(start, bio);
			bio_endio(bio);
			return;
		}
	}

	/* Both failed */
	bio->bi_status = BLK_STS_IOERR;
	bio_endio(bio);
}

/* Work handler */
static void ssr_work_fn(struct work_struct *work)
{
	struct ssr_work *sw = container_of(work, struct ssr_work, work);
	struct bio *bio = sw->bio;

	if (bio_op(bio) == REQ_OP_READ)
		do_read(bio);
	else
		do_write(bio);

	kfree(sw);
}

/* Submit bio handler */
static blk_qc_t ssr_submit_bio(struct bio *bio)
{
	struct ssr_work *sw;

	/* Bounds check */
	if (bio->bi_iter.bi_sector + bio_sectors(bio) > LOGICAL_DISK_SECTORS) {
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	/* Queue work */
	sw = kmalloc(sizeof(*sw), GFP_NOIO);
	if (!sw) {
		bio->bi_status = BLK_STS_RESOURCE;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	sw->bio = bio;
	INIT_WORK(&sw->work, ssr_work_fn);
	queue_work(wq, &sw->work);

	return BLK_QC_T_NONE;
}

static int __init ssr_init(void)
{
	int err;

	err = register_blkdev(SSR_MAJOR, "ssr");
	if (err < 0)
		return err;

	disk1 = blkdev_get_by_path(PHYSICAL_DISK1_NAME,
			FMODE_READ | FMODE_WRITE | FMODE_EXCL, THIS_MODULE);
	if (IS_ERR(disk1)) {
		err = PTR_ERR(disk1);
		goto e1;
	}

	disk2 = blkdev_get_by_path(PHYSICAL_DISK2_NAME,
			FMODE_READ | FMODE_WRITE | FMODE_EXCL, THIS_MODULE);
	if (IS_ERR(disk2)) {
		err = PTR_ERR(disk2);
		goto e2;
	}

	wq = alloc_workqueue("ssr", WQ_MEM_RECLAIM, 0);
	if (!wq) {
		err = -ENOMEM;
		goto e3;
	}

	gd = alloc_disk(1);
	if (!gd) {
		err = -ENOMEM;
		goto e4;
	}

	q = blk_alloc_queue(ssr_submit_bio, NUMA_NO_NODE);
	if (!q) {
		err = -ENOMEM;
		goto e5;
	}

	gd->major = SSR_MAJOR;
	gd->first_minor = SSR_FIRST_MINOR;
	gd->fops = &fops;
	gd->queue = q;
	snprintf(gd->disk_name, DISK_NAME_LEN, "ssr");
	set_capacity(gd, LOGICAL_DISK_SECTORS);
	blk_queue_logical_block_size(q, KERNEL_SECTOR_SIZE);

	add_disk(gd);
	return 0;

e5:	put_disk(gd);
e4:	destroy_workqueue(wq);
e3:	blkdev_put(disk2, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
e2:	blkdev_put(disk1, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
e1:	unregister_blkdev(SSR_MAJOR, "ssr");
	return err;
}

static void __exit ssr_exit(void)
{
	del_gendisk(gd);
	blk_cleanup_queue(q);
	put_disk(gd);
	destroy_workqueue(wq);
	blkdev_put(disk2, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
	blkdev_put(disk1, FMODE_READ | FMODE_WRITE | FMODE_EXCL);
	unregister_blkdev(SSR_MAJOR, "ssr");
}

module_init(ssr_init);
module_exit(ssr_exit);
