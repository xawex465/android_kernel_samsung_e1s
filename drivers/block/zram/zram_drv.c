/*
 * Compressed RAM block device
 *
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 *               2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 */

#define KMSG_COMPONENT "zram"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <linux/idr.h>
#include <linux/sysfs.h>
#include <linux/debugfs.h>
#include <linux/cpuhotplug.h>
#include <linux/part_stat.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/mman.h>
#include <linux/statfs.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/list.h>
#include <uapi/linux/falloc.h>
#include <uapi/linux/sched/types.h>
#include <trace/hooks/mm.h>

#include "zram_drv.h"
#include "../loop.h"

#define print_hex_dump_fmt(src, size) \
	print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 16, 1, src, size, 1)

static DEFINE_IDR(zram_index_idr);
/* idr index must be protected */
static DEFINE_MUTEX(zram_index_mutex);

static int zram_major;
static const char *default_compressor = "lzo-rle";

/* Module params (documentation at end) */
static unsigned int num_devices = 1;
/*
 * Pages that compress to sizes equals or greater than this are stored
 * uncompressed in memory.
 */
static size_t huge_class_size;

static const struct block_device_operations zram_devops;

static void zram_free_page(struct zram *zram, size_t index);
static int zram_bvec_read(struct zram *zram, struct bio_vec *bvec,
				u32 index, int offset, struct bio *bio);


static int zram_slot_trylock(struct zram *zram, u32 index)
{
	return bit_spin_trylock(ZRAM_LOCK, &zram->table[index].flags);
}

static void zram_slot_lock(struct zram *zram, u32 index)
{
	bit_spin_lock(ZRAM_LOCK, &zram->table[index].flags);
}

static void zram_slot_unlock(struct zram *zram, u32 index)
{
	bit_spin_unlock(ZRAM_LOCK, &zram->table[index].flags);
}

static inline bool init_done(struct zram *zram)
{
	return zram->disksize;
}

static inline struct zram *dev_to_zram(struct device *dev)
{
	return (struct zram *)dev_to_disk(dev)->private_data;
}

static unsigned long zram_get_handle(struct zram *zram, u32 index)
{
	return zram->table[index].handle;
}

static void zram_set_handle(struct zram *zram, u32 index, unsigned long handle)
{
	zram->table[index].handle = handle;
}

/* flag operations require table entry bit_spin_lock() being held */
static bool zram_test_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	return zram->table[index].flags & BIT(flag);
}

static void zram_set_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	zram->table[index].flags |= BIT(flag);
}

static void zram_clear_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	zram->table[index].flags &= ~BIT(flag);
}

static inline void zram_set_element(struct zram *zram, u32 index,
			unsigned long element)
{
	zram->table[index].element = element;
}

static unsigned long zram_get_element(struct zram *zram, u32 index)
{
	return zram->table[index].element;
}

static size_t zram_get_obj_size(struct zram *zram, u32 index)
{
	return zram->table[index].flags & (BIT(ZRAM_FLAG_SHIFT) - 1);
}

static void zram_set_obj_size(struct zram *zram,
					u32 index, size_t size)
{
	unsigned long flags = zram->table[index].flags >> ZRAM_FLAG_SHIFT;

	zram->table[index].flags = (flags << ZRAM_FLAG_SHIFT) | size;
}

static inline bool zram_allocated(struct zram *zram, u32 index)
{
	return zram_get_obj_size(zram, index) ||
			zram_test_flag(zram, index, ZRAM_SAME) ||
			zram_test_flag(zram, index, ZRAM_WB);
}

#ifdef CONFIG_ZRAM_PERF_STAT
static void zram_perf_io_end(struct zram_wb_work *zw, int rw)
{
	struct zram *zram = zw->zram;
	struct zram_perf_stat *perf_stat = &zram->stats.perf_stat[rw];
	unsigned long nr_pages;
	ktime_t delta;

	if (!zram->perf_stat_enabled)
		return;

	if (zw->nr_pages != NR_ZWBS)
		return;

	nr_pages = atomic64_add_return(NR_ZWBS, &perf_stat->nr_pages);
	if (atomic64_dec_return(&perf_stat->nr_io))
		return;

	delta = ktime_sub(ktime_get_boottime(), perf_stat->start);
	atomic64_add(delta, &perf_stat->time);
	atomic64_add(nr_pages, &perf_stat->cnt);
	atomic64_sub(nr_pages, &perf_stat->nr_pages);
}

static void zram_perf_io_start(struct zram_wb_work *zw, int rw)
{
	struct zram *zram = zw->zram;
	struct zram_perf_stat *perf_stat = &zram->stats.perf_stat[rw];

	if (!zram->perf_stat_enabled)
		return;

	if (zw->nr_pages != NR_ZWBS)
		return;

	if (atomic64_inc_return(&perf_stat->nr_io) == 1)
		perf_stat->start = ktime_get_boottime();
}

static ssize_t perf_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret = 0;
	int i;
	u64 cnt, time, tp;

	if (!zram->perf_stat_enabled)
		return ret;

	for (i = 0; i < NR_IO_TYPES; i++) {
		cnt = atomic64_read(&zram->stats.perf_stat[i].cnt);
		time = atomic64_read(&zram->stats.perf_stat[i].time);
		tp = cnt * NSEC_PER_SEC * PAGE_SIZE / 1024 / 1024 / time;
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				"%5s: %8llu MB/s\n", i ? "WRITE" : "READ", tp);
	}
	return ret;
}

static ssize_t perf_stat_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	int i;
	bool val;

	if (!kstrtobool(buf, &val)) {
		zram->perf_stat_enabled = val;
		for (i = 0; i < NR_IO_TYPES; i++)
			memset(&zram->stats.perf_stat[i], 0x00,
					sizeof(struct zram_perf_stat));
	}
	return len;
}

static DEVICE_ATTR_RW(perf_stat);
#endif

#if PAGE_SIZE != 4096
static inline bool is_partial_io(struct bio_vec *bvec)
{
	return bvec->bv_len != PAGE_SIZE;
}
#else
static inline bool is_partial_io(struct bio_vec *bvec)
{
	return false;
}
#endif

/*
 * Check if request is within bounds and aligned on zram logical blocks.
 */
static inline bool valid_io_request(struct zram *zram,
		sector_t start, unsigned int size)
{
	u64 end, bound;

	/* unaligned request */
	if (unlikely(start & (ZRAM_SECTOR_PER_LOGICAL_BLOCK - 1)))
		return false;
	if (unlikely(size & (ZRAM_LOGICAL_BLOCK_SIZE - 1)))
		return false;

	end = start + (size >> SECTOR_SHIFT);
	bound = zram->disksize >> SECTOR_SHIFT;
	/* out of range range */
	if (unlikely(start >= bound || end > bound || start > end))
		return false;

	/* I/O request is valid */
	return true;
}

static void update_position(u32 *index, int *offset, struct bio_vec *bvec)
{
	*index  += (*offset + bvec->bv_len) / PAGE_SIZE;
	*offset = (*offset + bvec->bv_len) % PAGE_SIZE;
}

static inline void update_used_max(struct zram *zram,
					const unsigned long pages)
{
	unsigned long old_max, cur_max;

	old_max = atomic_long_read(&zram->stats.max_used_pages);

	do {
		cur_max = old_max;
		if (pages > cur_max)
			old_max = atomic_long_cmpxchg(
				&zram->stats.max_used_pages, cur_max, pages);
	} while (old_max != cur_max);
}

static inline void zram_fill_page(void *ptr, unsigned long len,
					unsigned long value)
{
	WARN_ON_ONCE(!IS_ALIGNED(len, sizeof(unsigned long)));
	memset_l(ptr, value, len / sizeof(unsigned long));
}

static bool page_same_filled(void *ptr, unsigned long *element)
{
	unsigned long *page;
	unsigned long val;
	unsigned int pos, last_pos = PAGE_SIZE / sizeof(*page) - 1;

	page = (unsigned long *)ptr;
	val = page[0];

	if (val != page[last_pos])
		return false;

	for (pos = 1; pos < last_pos; pos++) {
		if (val != page[pos])
			return false;
	}

	*element = val;

	return true;
}

static ssize_t initstate_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u32 val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	val = init_done(zram);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%u\n", val);
}

static ssize_t disksize_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", zram->disksize);
}

static ssize_t mem_limit_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 limit;
	char *tmp;
	struct zram *zram = dev_to_zram(dev);

	limit = memparse(buf, &tmp);
	if (buf == tmp) /* no chars parsed, invalid input */
		return -EINVAL;

	down_write(&zram->init_lock);
	zram->limit_pages = PAGE_ALIGN(limit) >> PAGE_SHIFT;
	up_write(&zram->init_lock);

	return len;
}

static ssize_t mem_used_max_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int err;
	unsigned long val;
	struct zram *zram = dev_to_zram(dev);

	err = kstrtoul(buf, 10, &val);
	if (err || val != 0)
		return -EINVAL;

	down_read(&zram->init_lock);
	if (init_done(zram)) {
		atomic_long_set(&zram->stats.max_used_pages,
				zs_get_total_pages(zram->mem_pool));
	}
	up_read(&zram->init_lock);

	return len;
}

/*
 * Mark all pages which are older than or equal to cutoff as IDLE.
 * Callers should hold the zram init lock in read mode
 */
static void mark_idle(struct zram *zram, ktime_t cutoff)
{
	int is_idle = 1;
	unsigned long nr_pages = zram->disksize >> PAGE_SHIFT;
	int index;

	for (index = 0; index < nr_pages; index++) {
		/*
		 * Do not mark ZRAM_UNDER_WB slot as ZRAM_IDLE to close race.
		 * See the comment in writeback_store.
		 */
		zram_slot_lock(zram, index);
		if (zram_allocated(zram, index) &&
				!zram_test_flag(zram, index, ZRAM_UNDER_WB)) {
#ifdef CONFIG_ZRAM_MEMORY_TRACKING
			is_idle = !cutoff || ktime_after(cutoff, zram->table[index].ac_time);
#endif
			if (is_idle)
				zram_set_flag(zram, index, ZRAM_IDLE);
		}
		zram_slot_unlock(zram, index);
	}
}

static ssize_t idle_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	ktime_t cutoff_time = 0;
	ssize_t rv = -EINVAL;

	if (!sysfs_streq(buf, "all")) {
		/*
		 * If it did not parse as 'all' try to treat it as an integer
		 * when we have memory tracking enabled.
		 */
		u64 age_sec;

		if (IS_ENABLED(CONFIG_ZRAM_MEMORY_TRACKING) && !kstrtoull(buf, 0, &age_sec))
			cutoff_time = ktime_sub(ktime_get_boottime(),
					ns_to_ktime(age_sec * NSEC_PER_SEC));
		else
			goto out;
	}

	down_read(&zram->init_lock);
	if (!init_done(zram))
		goto out_unlock;

	/*
	 * A cutoff_time of 0 marks everything as idle, this is the
	 * "all" behavior.
	 */
	mark_idle(zram, cutoff_time);
	rv = len;

out_unlock:
	up_read(&zram->init_lock);
out:
	return rv;
}

#ifdef CONFIG_ZRAM_WRITEBACK
static ssize_t writeback_limit_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	u64 val;
	ssize_t ret = -EINVAL;

	if (kstrtoull(buf, 10, &val))
		return ret;

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	zram->wb_limit_enable = val;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);
	ret = len;

	return ret;
}

static ssize_t writeback_limit_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	bool val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	val = zram->wb_limit_enable;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%d\n", val);
}

static ssize_t writeback_limit_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	u64 val;
	ssize_t ret = -EINVAL;

	if (kstrtoull(buf, 10, &val))
		return ret;

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	zram->bd_wb_limit = val;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);
	ret = len;

	return ret;
}

static ssize_t writeback_limit_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u64 val;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	spin_lock(&zram->wb_limit_lock);
	val = zram->bd_wb_limit;
	spin_unlock(&zram->wb_limit_lock);
	up_read(&zram->init_lock);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", val);
}

static void reset_bdev(struct zram *zram)
{
	struct block_device *bdev;

	if (!zram->backing_dev)
		return;

	bdev = zram->bdev;
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
	/* hope filp_close flush all of IO */
	filp_close(zram->backing_dev, NULL);
	zram->backing_dev = NULL;
	zram->bdev = NULL;
	zram->disk->fops = &zram_devops;
	kvfree(zram->bitmap);
	zram->bitmap = NULL;
#ifdef CONFIG_ZRAM_RAMPLUS
	deinit_ramplus(zram);
#endif
}

static ssize_t backing_dev_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct file *file;
	struct zram *zram = dev_to_zram(dev);
	char *p;
	ssize_t ret;

	down_read(&zram->init_lock);
	file = zram->backing_dev;
	if (!file) {
		memcpy(buf, "none\n", 5);
		up_read(&zram->init_lock);
		return 5;
	}

	p = file_path(file, buf, PAGE_SIZE - 1);
	if (IS_ERR(p)) {
		ret = PTR_ERR(p);
		goto out;
	}

	ret = strlen(p);
	memmove(buf, p, ret);
	buf[ret++] = '\n';
out:
	up_read(&zram->init_lock);
	return ret;
}

static ssize_t backing_dev_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	char *file_name;
	size_t sz;
	struct file *backing_dev = NULL;
	struct inode *inode;
	struct address_space *mapping;
	unsigned int bitmap_sz;
	unsigned long nr_pages, *bitmap = NULL;
	struct block_device *bdev = NULL;
	int err;
	struct zram *zram = dev_to_zram(dev);

	file_name = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!file_name)
		return -ENOMEM;

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		pr_info("Can't setup backing device for initialized device\n");
		err = -EBUSY;
		goto out;
	}

	strscpy(file_name, buf, PATH_MAX);
	/* ignore trailing newline */
	sz = strlen(file_name);
	if (sz > 0 && file_name[sz - 1] == '\n')
		file_name[sz - 1] = 0x00;

	backing_dev = filp_open_block(file_name, O_RDWR|O_LARGEFILE, 0);
	if (IS_ERR(backing_dev)) {
		err = PTR_ERR(backing_dev);
		backing_dev = NULL;
		goto out;
	}

	mapping = backing_dev->f_mapping;
	inode = mapping->host;

	/* Support only block device in this moment */
	if (!S_ISBLK(inode->i_mode)) {
		err = -ENOTBLK;
		goto out;
	}

	bdev = blkdev_get_by_dev(inode->i_rdev,
			FMODE_READ | FMODE_WRITE | FMODE_EXCL, zram);
	if (IS_ERR(bdev)) {
		err = PTR_ERR(bdev);
		bdev = NULL;
		goto out;
	}

	nr_pages = i_size_read(inode) >> PAGE_SHIFT;
	bitmap_sz = BITS_TO_LONGS(nr_pages) * sizeof(long);
	bitmap = kvzalloc(bitmap_sz, GFP_KERNEL);
	if (!bitmap) {
		err = -ENOMEM;
		goto out;
	}

	reset_bdev(zram);

#ifdef CONFIG_ZRAM_RAMPLUS
	err = init_ramplus(zram, nr_pages);
	if (err)
		goto out;
#endif
	zram->bdev = bdev;
	zram->backing_dev = backing_dev;
	zram->bitmap = bitmap;
	zram->nr_pages = nr_pages;
	up_write(&zram->init_lock);

	pr_info("setup backing device %s\n", file_name);
	kfree(file_name);

	return len;
out:
	kvfree(bitmap);

	if (bdev)
		blkdev_put(bdev, FMODE_READ | FMODE_WRITE | FMODE_EXCL);

	if (backing_dev)
		filp_close(backing_dev, NULL);

	up_write(&zram->init_lock);

	kfree(file_name);

	return err;
}

#ifdef CONFIG_ZRAM_RAMPLUS
static bool is_app_launch;
static bool is_lzorle;
static unsigned char lzo_marker[4] = {0x11, 0x00, 0x00};
static const char * const keywords[] = {"Prev", "This", "Next"};
static struct kobject *zram_kobject;

static unsigned long chunk_to_blk_idx(unsigned long idx)
{
	return idx * NR_ZWBS;
}

static unsigned long blk_to_chunk_idx(unsigned long idx)
{
	return idx / NR_ZWBS;
}

static bool is_ppr_idx(struct zram *zram, unsigned long idx)
{
	return idx > zram->nr_lru_pages;
}

static unsigned long alloc_chunk_bdev(struct zram *zram, bool ppr)
{
	unsigned long chunk_idx;
	unsigned long max_idx;
	unsigned long blk_idx;
	unsigned long flags;
	int i;

	if (ppr) {
		chunk_idx = blk_to_chunk_idx(zram->nr_lru_pages) + 1;
		max_idx = blk_to_chunk_idx(zram->nr_pages);
	} else {
		chunk_idx = 1;
		max_idx = blk_to_chunk_idx(zram->nr_lru_pages);
	}
retry:
	/* skip 0 bit to confuse zram.handle = 0 */
	chunk_idx = find_next_zero_bit(zram->chunk_bitmap, max_idx, chunk_idx);
	if (chunk_idx == max_idx)
		return 0;

	spin_lock_irqsave(&zram->bitmap_lock, flags);
	if (test_and_set_bit(chunk_idx, zram->chunk_bitmap)) {
		spin_unlock_irqrestore(&zram->bitmap_lock, flags);
		goto retry;
	}
	blk_idx = chunk_to_blk_idx(chunk_idx);
	for (i = 0; i < NR_ZWBS; i++)
		BUG_ON(test_and_set_bit(blk_idx + i, zram->bitmap));
	spin_unlock_irqrestore(&zram->bitmap_lock, flags);
	atomic64_add(NR_ZWBS, &zram->stats.bd_count);
	if (ppr)
		atomic64_add(NR_ZWBS, &zram->stats.bd_ppr_count);
	return blk_idx;
}

static unsigned long alloc_block_bdev(struct zram *zram)
{
	unsigned long blk_idx = 1;
	unsigned long flags;
retry:
	/* skip 0 bit to confuse zram.handle = 0 */
	blk_idx = find_next_zero_bit(zram->bitmap, zram->nr_lru_pages, blk_idx);
	if (blk_idx == zram->nr_lru_pages)
		return 0;

	spin_lock_irqsave(&zram->bitmap_lock, flags);
	if (test_and_set_bit(blk_idx, zram->bitmap)) {
		spin_unlock_irqrestore(&zram->bitmap_lock, flags);
		goto retry;
	}
	set_bit(blk_to_chunk_idx(blk_idx), zram->chunk_bitmap);
	spin_unlock_irqrestore(&zram->bitmap_lock, flags);
	atomic64_inc(&zram->stats.bd_count);
	return blk_idx;
}

static void free_chunk_bdev(struct zram *zram, unsigned long chunk_idx)
{
	unsigned long blk_idx;
	unsigned long flags;
	int i;

	blk_idx = chunk_to_blk_idx(chunk_idx);
	spin_lock_irqsave(&zram->bitmap_lock, flags);
	for (i = 0; i < NR_ZWBS; i++) {
		if (test_bit(blk_idx + i, zram->bitmap)) {
			spin_unlock_irqrestore(&zram->bitmap_lock, flags);
			return;
		}
	}
	clear_bit(chunk_idx, zram->chunk_bitmap);
	spin_unlock_irqrestore(&zram->bitmap_lock, flags);
}

static void free_block_bdev(struct zram *zram, unsigned long blk_idx)
{
	int was_set;
	unsigned long flags;
	bool ppr = is_ppr_idx(zram, blk_idx);

	spin_lock_irqsave(&zram->wb_table_lock, flags);
	if (!zram->wb_table || zram->wb_table[blk_idx] == 0)
		goto out;
	zram->wb_table[blk_idx]--;
	atomic64_dec(&zram->stats.bd_objcnt);
	if (ppr)
		atomic64_dec(&zram->stats.bd_ppr_objcnt);
	if (zram->wb_table[blk_idx] > 0) {
		spin_unlock_irqrestore(&zram->wb_table_lock, flags);
		return;
	}
out:
	spin_unlock_irqrestore(&zram->wb_table_lock, flags);
	was_set = test_and_clear_bit(blk_idx, zram->bitmap);
	WARN_ON_ONCE(!was_set);
	atomic64_dec(&zram->stats.bd_count);
	if (ppr)
		atomic64_dec(&zram->stats.bd_ppr_count);
	free_chunk_bdev(zram, blk_to_chunk_idx(blk_idx));
}

static void zram_inc_wb_table(struct zram *zram, unsigned long blk_idx)
{
	unsigned long flags;

	spin_lock_irqsave(&zram->wb_table_lock, flags);
	if (zram->wb_table)
		zram->wb_table[blk_idx]++;
	spin_unlock_irqrestore(&zram->wb_table_lock, flags);
}

static void zram_dec_wb_table(struct zram *zram, unsigned long blk_idx)
{
	unsigned long flags;

	spin_lock_irqsave(&zram->wb_table_lock, flags);
	if (!zram->wb_table) {
		spin_unlock_irqrestore(&zram->wb_table_lock, flags);
		return;
	}
	zram->wb_table[blk_idx]--;
	if (zram->wb_table[blk_idx] > 0) {
		spin_unlock_irqrestore(&zram->wb_table_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&zram->wb_table_lock, flags);
	clear_bit(blk_idx, zram->bitmap);
	atomic64_dec(&zram->stats.bd_count);
	if (is_ppr_idx(zram, blk_idx))
		atomic64_dec(&zram->stats.bd_ppr_count);
	free_chunk_bdev(zram, blk_to_chunk_idx(blk_idx));
}

static bool is_bdev_avail(struct zram *zram)
{
	struct loop_device *lo;
	struct inode *inode;
	struct dentry *root;
	struct kstatfs statbuf;
	u64 min_free_blocks;
	int ret;

	if (!zram->bdev || !zram->bdev->bd_disk)
		return false;

	lo = zram->bdev->bd_disk->private_data;
	if (!lo || !lo->lo_backing_file)
		return false;

	inode = lo->lo_backing_file->f_mapping->host;
	root = inode->i_sb->s_root;
	if (!root->d_sb->s_op->statfs)
		return false;

	ret = root->d_sb->s_op->statfs(root, &statbuf);
	if (ret)
		return false;
	/*
	 * To guarantee "reserved block(133MB on Q-os)" for system,
	 * SQZR is triggered only when devices have enough storage free space
	 * more than SZ_1G or reserved block * 2.
	 */
	min_free_blocks = max_t(u64, SZ_1G / statbuf.f_bsize,
			(statbuf.f_bfree - statbuf.f_bavail) * 2);
	if (statbuf.f_bavail < min_free_blocks)
		return false;

	return true;
}

static bool zram_wb_available(struct zram *zram)
{
	if (!zram->backing_dev || !is_bdev_avail(zram))
		return false;

	spin_lock(&zram->wb_limit_lock);
	if (zram->wb_limit_enable && !zram->bd_wb_limit) {
		spin_unlock(&zram->wb_limit_lock);
		return false;
	}
	spin_unlock(&zram->wb_limit_lock);

	if (atomic64_read(&zram->stats.bd_objcnt) >= zram->nr_pages * 4)
		return false;
	return true;
}

static void fallocate_block(struct zram *zram, unsigned long blk_idx)
{
	struct block_device *bdev = zram->bdev;

	if (!bdev)
		return;

	mutex_lock(&zram->blk_bitmap_lock);
	/* check 2MB block bitmap. if unset, fallocate 2MB block at once */
	if (!test_and_set_bit(blk_idx / NR_FALLOC_PAGES, zram->blk_bitmap)) {
		struct loop_device *lo = bdev->bd_disk->private_data;
		struct file *file = lo->lo_backing_file;
		loff_t pos = (blk_idx & FALLOC_ALIGN_MASK) << PAGE_SHIFT;
		loff_t len = NR_FALLOC_PAGES << PAGE_SHIFT;
		int mode = FALLOC_FL_KEEP_SIZE;
		int ret;

		file_start_write(file);
		ret = file->f_op->fallocate(file, mode, pos, len);
		if (ret)
			pr_err("%s pos %lx failed %d\n", __func__, (unsigned long)pos, ret);
		file_end_write(file);
	}
	mutex_unlock(&zram->blk_bitmap_lock);
}

static void free_writeback_buffer(struct zram_writeback_buffer *buf)
{
	struct zwbs **zwbs;
	int i;

	if (!buf)
		return;

	zwbs = buf->zwbs;
	for (i = 0; i < NR_ZWBS; i++) {
		if (!zwbs[i])
			break;
		if (zwbs[i]->page)
			__free_page(zwbs[i]->page);
		kfree(zwbs[i]);
	}
	kfree(buf);
}

static struct zram_writeback_buffer *alloc_writeback_buffer(void)
{
	struct zram_writeback_buffer *buf;
	struct zwbs **zwbs;
	int i;

	buf = kzalloc(sizeof(struct zram_writeback_buffer), GFP_KERNEL);
	if (!buf)
		return NULL;

	zwbs = buf->zwbs;
	for (i = 0; i < NR_ZWBS; i++) {
		zwbs[i] = kzalloc(sizeof(struct zwbs), GFP_KERNEL);
		if (!zwbs[i])
			goto out;
		zwbs[i]->page = alloc_page(GFP_KERNEL);
		if (!zwbs[i]->page)
			goto out;
	}
	return buf;

out:
	free_writeback_buffer(buf);
	return NULL;
}

static void mark_end_of_page(struct zwbs *zwbs)
{
	struct zram_wb_header *zhdr;
	struct page *page = zwbs->page;
	int offset = zwbs->off;
	void *mem;

	if (offset + sizeof(struct zram_wb_header) <= PAGE_SIZE) {
		mem = kmap_atomic(page);
		zhdr = (struct zram_wb_header *)(mem + offset);
		zhdr->index = UINT_MAX;
		zhdr->size = 0;
		kunmap_atomic(mem);
	}
}

static void print_hex_dump_pages(struct page **src_page, int nr_pages, int idx)
{
	int i, min_idx, max_idx;
	void *src;

	if (idx < 0 || idx > NR_ZWBS - 1)
		return;

	min_idx = (nr_pages == 1) ? idx : max_t(int, idx - 1, 0);
	max_idx = (nr_pages == 1) ? idx : min_t(int, idx + 1, NR_ZWBS - 1);
	for (i = min_idx; i <= max_idx; i++) {
		pr_err("%s page\n", keywords[i - idx + 1]);
		src = kmap_atomic(src_page[i]);
		print_hex_dump_fmt(src, PAGE_SIZE);
		kunmap_atomic(src);
	}
}

static void check_marker(void *addr, int size, struct page **pages, int nr_pages, int idx)
{
	if (!is_lzorle || size == PAGE_SIZE)
		return;

	if (!memcmp(addr + size - 3, lzo_marker, 3))
		return;

	pr_err("%ps marker error, addr=0x%px len=%u\n", (void *)_RET_IP_, addr, size);
	if (pages)
		print_hex_dump_pages(pages, nr_pages, idx);
	else
		print_hex_dump_fmt(addr, size);
	BUG();
}

static int zram_writeback_fill_page(struct zram *zram, u32 index,
				struct zwbs **zwbs, int idx, bool ppr)
{
	struct zram_wb_header *zhdr;
	struct page *page = zwbs[idx]->page;
	int offset = zwbs[idx]->off;
	unsigned long handle;
	void *src, *dst;
	int size, sizes[2];
	int header_sz = 0;

	zram_slot_lock(zram, index);
	if (!zram_allocated(zram, index) ||
			!zram_test_flag(zram, index, ZRAM_IDLE) ||
			zram_test_flag(zram, index, ZRAM_WB) ||
			zram_test_flag(zram, index, ZRAM_SAME) ||
			zram_test_flag(zram, index, ZRAM_UNDER_WB)) {
		zram_slot_unlock(zram, index);
		return 0;
	}
	size = zram_get_obj_size(zram, index);
	if (ppr || size != PAGE_SIZE)
		header_sz = sizeof(struct zram_wb_header);

	if (((!ppr || idx == NR_ZWBS - 1) &&
			offset + header_sz + size > PAGE_SIZE) ||
			offset + header_sz > PAGE_SIZE) {
		zram_slot_unlock(zram, index);
		return -ENOSPC;
	}
	/*
	 * Clearing ZRAM_UNDER_WB is duty of caller.
	 * IOW, zram_free_page never clear it.
	 */
	zram_set_flag(zram, index, ZRAM_UNDER_WB);
	/* Need for hugepage writeback racing */
	zram_set_flag(zram, index, ZRAM_IDLE);

	handle = zram_get_element(zram, index);
	if (!handle) {
		zram_clear_flag(zram, index, ZRAM_UNDER_WB);
		zram_clear_flag(zram, index, ZRAM_IDLE);
		zram_slot_unlock(zram, index);
		return -ENOENT;
	}
	src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
	dst = kmap_atomic(page);
	if (header_sz) {
		zhdr = (struct zram_wb_header *)(dst + offset);
		zhdr->index = index;
		zhdr->size = size;
		dst = (u8 *)(zhdr + 1);
	}
	if (offset + header_sz + size > PAGE_SIZE) {
		sizes[0] = PAGE_SIZE - (offset + header_sz);
		sizes[1] = size - sizes[0];
		memcpy(dst, src, sizes[0]);
		kunmap_atomic(dst);
		dst = kmap_atomic(zwbs[idx + 1]->page);
		memcpy(dst, src + sizes[0], sizes[1]);
		zwbs[idx + 1]->off = sizes[1];
	} else {
		memcpy(dst, src, size);
	}
	kunmap_atomic(dst);
	check_marker(src, size, NULL, 0, 0);
	zs_unmap_object(zram->mem_pool, handle);
	zram_slot_unlock(zram, index);

	return size;
}

static void zram_writeback_clear_flag(struct zram *zram, u32 index)
{
	zram_slot_lock(zram, index);
	if (zram_allocated(zram, index)) {
		zram_clear_flag(zram, index, ZRAM_UNDER_WB);
		zram_clear_flag(zram, index, ZRAM_IDLE);
		zram_entry_move_list(zram, NULL, index);
	}
	zram_slot_unlock(zram, index);
}

static void zram_writeback_clear_flags(struct zram *zram, struct zwbs **zwbs)
{
	int i, j;

	for (i = 0; i < NR_ZWBS; i++)
		for (j = 0; j < zwbs[i]->cnt; j++)
			zram_writeback_clear_flag(zram, zwbs[i]->entry[j].index);
}

static void zram_update_max_stats(struct zram *zram)
{
	unsigned long bd_count, bd_size, bd_ppr_count, bd_ppr_size;

	bd_count = atomic64_read(&zram->stats.bd_count);
	if (bd_count <= atomic64_read(&zram->stats.bd_max_count))
		return;

	bd_size = atomic64_read(&zram->stats.bd_size);
	bd_ppr_count = atomic64_read(&zram->stats.bd_ppr_count);
	bd_ppr_size = atomic64_read(&zram->stats.bd_ppr_size);
	atomic64_set(&zram->stats.bd_max_count, bd_count);
	atomic64_set(&zram->stats.bd_max_size, bd_size);
	atomic64_set(&zram->stats.bd_ppr_max_count, bd_ppr_count);
	atomic64_set(&zram->stats.bd_ppr_max_size, bd_ppr_size);
}

static void zram_reset_stats(struct zram *zram)
{
	atomic64_set(&zram->stats.bd_max_count, 0);
	atomic64_set(&zram->stats.bd_max_size, 0);
	atomic64_set(&zram->stats.bd_ppr_max_count, 0);
	atomic64_set(&zram->stats.bd_ppr_max_size, 0);
}

static void zram_writeback_done(struct zram *zram,
		struct zwbs *zwbs, unsigned long blk_idx)
{
	unsigned long index;
	unsigned int offset;
	unsigned int size;
	unsigned int count = zwbs->cnt;
	struct zram_wb_entry *entry = zwbs->entry;
	int i;
	unsigned long flags;
	bool ppr = is_ppr_idx(zram, blk_idx);

	if (!count) {
		free_block_bdev(zram, blk_idx);
		return;
	}
	spin_lock_irqsave(&zram->wb_table_lock, flags);
	if (!zram->wb_table) {
		spin_unlock_irqrestore(&zram->wb_table_lock, flags);
		return;
	}
	zram->wb_table[blk_idx] = count;
	spin_unlock_irqrestore(&zram->wb_table_lock, flags);
	atomic64_add(count, &zram->stats.bd_objwrites);
	atomic64_add(count, &zram->stats.bd_objcnt);
	if (ppr)
		atomic64_add(count, &zram->stats.bd_ppr_objcnt);

	for (i = 0; i < count; i++) {
		index = entry[i].index;
		offset = entry[i].offset;
		size = entry[i].size;
		/*
		 * We released zram_slot_lock so need to check if the slot was
		 * changed. If there is freeing for the slot, we can catch it
		 * easily by zram_allocated.
		 * A subtle case is the slot is freed/reallocated/marked as
		 * ZRAM_IDLE again. To close the race, idle_store doesn't
		 * mark ZRAM_IDLE once it found the slot was ZRAM_UNDER_WB.
		 * Thus, we could close the race by checking ZRAM_IDLE bit.
		 */
		zram_slot_lock(zram, index);
		if (!zram_allocated(zram, index) ||
				!zram_test_flag(zram, index, ZRAM_IDLE)) {
			zram_clear_flag(zram, index, ZRAM_UNDER_WB);
			zram_clear_flag(zram, index, ZRAM_IDLE);
			free_block_bdev(zram, blk_idx);
			zram_slot_unlock(zram, index);
			continue;
		}

		zram_free_page(zram, index);
		zram_clear_flag(zram, index, ZRAM_UNDER_WB);
		zram_set_flag(zram, index, ZRAM_WB);
		atomic64_add(size, &zram->stats.bd_size);
		if (ppr) {
			zram_set_flag(zram, index, ZRAM_PPR);
			atomic64_add(size, &zram->stats.bd_ppr_size);
		}
		/* record element as "blk_idx|offset|size" */
		if (size == PAGE_SIZE)
			size = 0;
		zram_set_element(zram, index,
				(blk_idx << IDX_SHIFT) | (offset << PAGE_SHIFT) | size);
		zram_slot_unlock(zram, index);
		atomic64_inc(&zram->stats.pages_stored);
	}
}

static void zram_writeback_done_work(struct work_struct *work)
{
	struct zram_wb_work *zw = container_of(work, struct zram_wb_work, work);
	struct zram *zram = zw->zram;
	struct zram_writeback_buffer *buf = zw->buf;
	struct bio *bio = zw->bio;
	unsigned long blk_idx = zw->handle;
	int nr_pages = zw->nr_pages;
	int i;

	if (bio->bi_status)
		zram_writeback_clear_flags(zram, buf->zwbs);

	for (i = 0; i < nr_pages; i++)
		zram_writeback_done(zram, buf->zwbs[i], blk_idx + i);

	zram_update_max_stats(zram);
	atomic64_add(nr_pages, &zram->stats.bd_writes);
	if (is_ppr_idx(zram, blk_idx))
		atomic64_add(nr_pages, &zram->stats.bd_ppr_writes);
	spin_lock(&zram->wb_limit_lock);
	if (zram->wb_limit_enable)
		zram->bd_wb_limit -= min_t(u64, nr_pages, zram->bd_wb_limit);
	spin_unlock(&zram->wb_limit_lock);

	bio_put(bio);
	free_writeback_buffer(buf);
	kfree(zw);
}

static void zram_writeback_page_end_io(struct bio *bio)
{
	struct page *page = bio->bi_io_vec[0].bv_page;
	struct zram_wb_work *zw = (struct zram_wb_work *)page_private(page);
	int errno = blk_status_to_errno(bio->bi_status);

	if (errno)
		pr_info("%s errno %d\n", __func__, errno);

#ifdef CONFIG_ZRAM_PERF_STAT
	zram_perf_io_end(zw, WRITE);
#endif
	INIT_WORK(&zw->work, zram_writeback_done_work);
	schedule_work(&zw->work);
}

static int zram_writeback_page(struct zram *zram, struct zram_writeback_buffer *buf, bool ppr)
{
	struct zram_wb_work *zw;
	struct zwbs **zwbs = buf->zwbs;
	struct bio *bio;
	unsigned long blk_idx;
	int i;

	blk_idx = alloc_chunk_bdev(zram, ppr);
	if (!blk_idx)
		goto out;

	/* fallocate 2MB block if not allocated yet */
	fallocate_block(zram, blk_idx);

	bio = bio_alloc(zram->bdev, NR_ZWBS, REQ_OP_WRITE, GFP_KERNEL);
	if (!bio)
		goto out;

	zw = kzalloc(sizeof(struct zram_wb_work), GFP_KERNEL);
	if (!zw) {
		bio_put(bio);
		goto out;
	}
	zw->nr_pages = NR_ZWBS;
	zw->zram = zram;
	zw->bio = bio;
	zw->handle = blk_idx;
	zw->buf = buf;
	set_page_private(zwbs[0]->page, (unsigned long)zw);

	bio->bi_end_io = zram_writeback_page_end_io;
	bio->bi_iter.bi_sector = blk_idx * (PAGE_SIZE >> 9);
	for (i = 0; i < NR_ZWBS; i++)
		bio_add_page(bio, zwbs[i]->page, PAGE_SIZE, 0);

#ifdef CONFIG_ZRAM_PERF_STAT
	zram_perf_io_start(zw, WRITE);
#endif
	submit_bio(bio);
	return 0;
out:
	if (blk_idx)
		for (i = 0; i < NR_ZWBS; i++)
			free_block_bdev(zram, blk_idx + i);
	zram_writeback_clear_flags(zram, zwbs);
	free_writeback_buffer(buf);
	return -ENOMEM;
}

static int zram_writeback_index(struct zram *zram, u32 index,
		struct zram_writeback_buffer **buf, bool ppr)
{
	struct zram_writeback_buffer *tmpbuf = *buf;
	struct zwbs **zwbs;
	int size, i, ret = 0;

retry:
	/* allocate new buffer for writeback */
	if (tmpbuf == NULL) {
		tmpbuf = alloc_writeback_buffer();
		if (tmpbuf == NULL)
			return -ENOMEM;
	}
	zwbs = tmpbuf->zwbs;
	i = tmpbuf->idx;

	size = zram_writeback_fill_page(zram, index, zwbs, i, ppr);
	if (size > 0) {
		struct zram_wb_entry *entry = zwbs[i]->entry;

		entry[zwbs[i]->cnt].index = index;
		entry[zwbs[i]->cnt].offset = zwbs[i]->off;
		entry[zwbs[i]->cnt].size = size;
		zwbs[i]->off += (size + sizeof(struct zram_wb_header));
		zwbs[i]->cnt++;
	}
	/* writeback if page is full/entry is full */
	if (size == -ENOSPC || zwbs[i]->cnt == ZRAM_WB_THRESHOLD) {
		mark_end_of_page(zwbs[i]);
		if (++tmpbuf->idx == NR_ZWBS) {
			ret = zram_writeback_page(zram, tmpbuf, ppr);
			tmpbuf = NULL;
		}
		if (ret == 0)
			goto retry;
	}
	*buf = tmpbuf;
	return ret;
}
#else
static unsigned long alloc_block_bdev(struct zram *zram)
{
	unsigned long blk_idx = 1;
retry:
	/* skip 0 bit to confuse zram.handle = 0 */
	blk_idx = find_next_zero_bit(zram->bitmap, zram->nr_pages, blk_idx);
	if (blk_idx == zram->nr_pages)
		return 0;

	if (test_and_set_bit(blk_idx, zram->bitmap))
		goto retry;

	atomic64_inc(&zram->stats.bd_count);
	return blk_idx;
}

static void free_block_bdev(struct zram *zram, unsigned long blk_idx)
{
	int was_set;

	was_set = test_and_clear_bit(blk_idx, zram->bitmap);
	WARN_ON_ONCE(!was_set);
	atomic64_dec(&zram->stats.bd_count);
}
#endif

static void zram_page_end_io(struct bio *bio)
{
	struct page *page = bio_first_page_all(bio);

	page_endio(page, op_is_write(bio_op(bio)),
			blk_status_to_errno(bio->bi_status));
	bio_put(bio);
}

/*
 * Returns 1 if the submission is successful.
 */
static int read_from_bdev_async(struct zram *zram, struct bio_vec *bvec,
			unsigned long entry, struct bio *parent)
{
	struct bio *bio;

	bio = bio_alloc(zram->bdev, 1, parent ? parent->bi_opf : REQ_OP_READ,
			GFP_NOIO);
	if (!bio)
		return -ENOMEM;

	bio->bi_iter.bi_sector = entry * (PAGE_SIZE >> 9);
	if (!bio_add_page(bio, bvec->bv_page, bvec->bv_len, bvec->bv_offset)) {
		bio_put(bio);
		return -EIO;
	}

	if (!parent)
		bio->bi_end_io = zram_page_end_io;
	else
		bio_chain(bio, parent);

	submit_bio(bio);
	return 1;
}

#define PAGE_WB_SIG "page_index="

#define PAGE_WRITEBACK 0
#define HUGE_WRITEBACK (1<<0)
#define IDLE_WRITEBACK (1<<1)


static ssize_t writeback_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	unsigned long nr_pages = zram->disksize >> PAGE_SHIFT;
	unsigned long index = 0;
	struct bio bio;
	struct bio_vec bio_vec;
	struct page *page;
	ssize_t ret = len;
	int mode, err;
	unsigned long blk_idx = 0;

	if (sysfs_streq(buf, "idle"))
		mode = IDLE_WRITEBACK;
	else if (sysfs_streq(buf, "huge"))
		mode = HUGE_WRITEBACK;
	else if (sysfs_streq(buf, "huge_idle"))
		mode = IDLE_WRITEBACK | HUGE_WRITEBACK;
	else {
		if (strncmp(buf, PAGE_WB_SIG, sizeof(PAGE_WB_SIG) - 1))
			return -EINVAL;

		if (kstrtol(buf + sizeof(PAGE_WB_SIG) - 1, 10, &index) ||
				index >= nr_pages)
			return -EINVAL;

		nr_pages = 1;
		mode = PAGE_WRITEBACK;
	}

	down_read(&zram->init_lock);
	if (!init_done(zram)) {
		ret = -EINVAL;
		goto release_init_lock;
	}

	if (!zram->backing_dev) {
		ret = -ENODEV;
		goto release_init_lock;
	}

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto release_init_lock;
	}

	for (; nr_pages != 0; index++, nr_pages--) {
		struct bio_vec bvec;

		bvec.bv_page = page;
		bvec.bv_len = PAGE_SIZE;
		bvec.bv_offset = 0;

		spin_lock(&zram->wb_limit_lock);
		if (zram->wb_limit_enable && !zram->bd_wb_limit) {
			spin_unlock(&zram->wb_limit_lock);
			ret = -EIO;
			break;
		}
		spin_unlock(&zram->wb_limit_lock);

		if (!blk_idx) {
			blk_idx = alloc_block_bdev(zram);
			if (!blk_idx) {
				ret = -ENOSPC;
				break;
			}
		}

		zram_slot_lock(zram, index);
		if (!zram_allocated(zram, index))
			goto next;

		if (zram_test_flag(zram, index, ZRAM_WB) ||
				zram_test_flag(zram, index, ZRAM_SAME) ||
				zram_test_flag(zram, index, ZRAM_UNDER_WB))
			goto next;

		if (mode & IDLE_WRITEBACK &&
			  !zram_test_flag(zram, index, ZRAM_IDLE))
			goto next;
		if (mode & HUGE_WRITEBACK &&
			  !zram_test_flag(zram, index, ZRAM_HUGE))
			goto next;
		/*
		 * Clearing ZRAM_UNDER_WB is duty of caller.
		 * IOW, zram_free_page never clear it.
		 */
		zram_set_flag(zram, index, ZRAM_UNDER_WB);
		/* Need for hugepage writeback racing */
		zram_set_flag(zram, index, ZRAM_IDLE);
		zram_slot_unlock(zram, index);
		if (zram_bvec_read(zram, &bvec, index, 0, NULL)) {
			zram_slot_lock(zram, index);
			zram_clear_flag(zram, index, ZRAM_UNDER_WB);
			zram_clear_flag(zram, index, ZRAM_IDLE);
			zram_slot_unlock(zram, index);
			continue;
		}

		bio_init(&bio, zram->bdev, &bio_vec, 1,
			 REQ_OP_WRITE | REQ_SYNC);
		bio.bi_iter.bi_sector = blk_idx * (PAGE_SIZE >> 9);

		bio_add_page(&bio, bvec.bv_page, bvec.bv_len,
				bvec.bv_offset);
		/*
		 * XXX: A single page IO would be inefficient for write
		 * but it would be not bad as starter.
		 */
		err = submit_bio_wait(&bio);
		if (err) {
			zram_slot_lock(zram, index);
			zram_clear_flag(zram, index, ZRAM_UNDER_WB);
			zram_clear_flag(zram, index, ZRAM_IDLE);
			zram_slot_unlock(zram, index);
			/*
			 * Return last IO error unless every IO were
			 * not suceeded.
			 */
			ret = err;
			continue;
		}

		atomic64_inc(&zram->stats.bd_writes);
		/*
		 * We released zram_slot_lock so need to check if the slot was
		 * changed. If there is freeing for the slot, we can catch it
		 * easily by zram_allocated.
		 * A subtle case is the slot is freed/reallocated/marked as
		 * ZRAM_IDLE again. To close the race, idle_store doesn't
		 * mark ZRAM_IDLE once it found the slot was ZRAM_UNDER_WB.
		 * Thus, we could close the race by checking ZRAM_IDLE bit.
		 */
		zram_slot_lock(zram, index);
		if (!zram_allocated(zram, index) ||
			  !zram_test_flag(zram, index, ZRAM_IDLE)) {
			zram_clear_flag(zram, index, ZRAM_UNDER_WB);
			zram_clear_flag(zram, index, ZRAM_IDLE);
			goto next;
		}

		zram_free_page(zram, index);
		zram_clear_flag(zram, index, ZRAM_UNDER_WB);
		zram_set_flag(zram, index, ZRAM_WB);
#ifdef CONFIG_ZRAM_RAMPLUS
		blk_idx <<= IDX_SHIFT;
		atomic64_inc(&zram->stats.bd_objcnt);
#endif
		zram_set_element(zram, index, blk_idx);
		blk_idx = 0;
		atomic64_inc(&zram->stats.pages_stored);
		spin_lock(&zram->wb_limit_lock);
		if (zram->wb_limit_enable && zram->bd_wb_limit > 0)
			zram->bd_wb_limit -=  1UL << (PAGE_SHIFT - 12);
		spin_unlock(&zram->wb_limit_lock);
next:
		zram_slot_unlock(zram, index);
	}

	if (blk_idx)
		free_block_bdev(zram, blk_idx);
	__free_page(page);
release_init_lock:
	up_read(&zram->init_lock);

	return ret;
}

#ifdef CONFIG_ZRAM_RAMPLUS
static void free_zw_pages(struct zram_wb_work *zw)
{
	int i;

	for (i = 0; i < zw->nr_pages; i++) {
		if (!zw->src_page[i])
			return;
		__free_page(zw->src_page[i]);
	}
}

static int alloc_zw_pages(struct zram_wb_work *zw)
{
	int i;

	for (i = 0; i < zw->nr_pages; i++) {
		zw->src_page[i] = alloc_page(GFP_NOIO|__GFP_HIGHMEM);
		if (!zw->src_page[i]) {
			pr_info("%s failed to alloc page", __func__);
			free_zw_pages(zw);
			return -ENOMEM;
		}
	}
	return 0;
}

static void copy_to_buf(void *dst, struct page **pages,
			unsigned int idx, unsigned int offset,
			unsigned int size)
{
	int sizes[2];
	u8 *src;

	sizes[0] = min_t(int, size, PAGE_SIZE - offset);
	sizes[1] = size - sizes[0];

	if (sizes[0]) {
		src = kmap_atomic(pages[idx]);
		memcpy(dst, src + offset, sizes[0]);
		kunmap_atomic(src);
	}
	if (sizes[1]) {
		src = kmap_atomic(pages[idx + 1]);
		memcpy(dst + sizes[0], src, sizes[1]);
		kunmap_atomic(src);
	}
}

static void zram_handle_remain(struct zram *zram, struct page **pages,
				unsigned int blk_idx, int nr_pages)
{
	struct zram_wb_header *zhdr;
	unsigned long alloced_pages;
	unsigned long handle;
	unsigned int idx = 0;
	unsigned int offset = 0;
	unsigned int size;
	int header_sz = sizeof(struct zram_wb_header);
	u32 index;
	u8 *mem, *dst;

	while (idx < nr_pages) {
		mem = kmap_atomic(pages[idx]);
		zhdr = (struct zram_wb_header *)(mem + offset);
		index = zhdr->index;
		size = zhdr->size;
		kunmap_atomic(mem);

		/* last object */
		if (index == UINT_MAX && size == 0) {
			idx++;
			offset = 0;
			continue;
		}

		/* corrupted page */
		if (index >= (zram->disksize >> PAGE_SHIFT) || size > PAGE_SIZE) {
			pr_err("%s %s zhdr error, index=%u size=%u\n",
				__func__, zram->compressor, index, size);
			print_hex_dump_pages(pages, nr_pages, idx);
			BUG();
		}

		zram_slot_lock(zram, index);
		if (!zram_allocated(zram, index) ||
			!zram_test_flag(zram, index, ZRAM_WB)) {
			zram_slot_unlock(zram, index);
			goto next;
		}
		handle = zram_get_element(zram, index);
		if ((handle >> IDX_SHIFT) != blk_idx + idx ||
			((handle >> PAGE_SHIFT) & (PAGE_SIZE - 1)) != offset ||
			(size == PAGE_SIZE && (handle & (PAGE_SIZE - 1)) != 0) ||
			(size != PAGE_SIZE && (handle & (PAGE_SIZE - 1)) != size)) {
			zram_slot_unlock(zram, index);
			goto next;
		}
		atomic64_inc(&zram->stats.bd_objreads);

		handle = zs_malloc(zram->mem_pool, size,
				__GFP_KSWAPD_RECLAIM |
				__GFP_NOWARN |
				__GFP_HIGHMEM |
				__GFP_MOVABLE |
				__GFP_CMA);
		if (IS_ERR((void *)handle)) {
			zram_slot_unlock(zram, index);
			break;
		}
		alloced_pages = zs_get_total_pages(zram->mem_pool);
		update_used_max(zram, alloced_pages);

		dst = zs_map_object(zram->mem_pool, handle, ZS_MM_WO);
		copy_to_buf(dst, pages, idx, offset + header_sz, size);
		check_marker(dst, size, pages, nr_pages, idx);
		zs_unmap_object(zram->mem_pool, handle);

		atomic64_add(size, &zram->stats.compr_data_size);
		zram_free_page(zram, index);
		zram_set_element(zram, index, handle);
		zram_set_obj_size(zram, index, size);
		if (size == PAGE_SIZE) {
			zram_set_flag(zram, index, ZRAM_HUGE);
			atomic64_inc(&zram->stats.huge_pages);
		}
		zram_entry_move_list(zram, NULL, index);
		zram_slot_unlock(zram, index);
		atomic64_inc(&zram->stats.pages_stored);
next:
		offset += (size + header_sz);
		if (offset >= PAGE_SIZE) {
			idx += offset / PAGE_SIZE;
			offset %= PAGE_SIZE;
		}
		/* check next offset again */
		if (offset + header_sz > PAGE_SIZE) {
			idx++;
			offset = 0;
		}
	}
}

static void zram_handle_comp_page(struct work_struct *work)
{
	struct zram_wb_work *zw = container_of(work, struct zram_wb_work, work);
	struct zram_wb_header *zhdr;
	struct zram *zram = zw->zram;
	struct zcomp_strm *zstrm;
	struct page **src_page = zw->src_page;
	struct page *dst_page = zw->dst_page;
	struct bio *bio = zw->bio;
	unsigned int blk_idx = zw->handle >> IDX_SHIFT;
	unsigned int offset = (zw->handle >> PAGE_SHIFT) & (PAGE_SIZE - 1);
	unsigned int size = zw->handle & (PAGE_SIZE - 1) ? : PAGE_SIZE;
	unsigned int page_idx = 0;
	int header_sz = sizeof(struct zram_wb_header);
	int ret = 0;
	int errno = blk_status_to_errno(bio->bi_status);
	u32 index;
	u8 *src, *dst, *src_decomp;
	bool spanned;

	if (errno) {
		pr_err("%s submit_bio errno %d\n", __func__, errno);
		goto out_err;
	}

	if (is_ppr_idx(zram, blk_idx)) {
		page_idx = blk_idx & ~ZWBS_ALIGN_MASK;
		blk_idx &= ZWBS_ALIGN_MASK;
	}

	src = kmap_atomic(src_page[page_idx]);
	zhdr = (struct zram_wb_header *)(src + offset);
	index = zhdr->index;
	if (zhdr->size != size) {
		pr_err("%s %s zhdr error, size should be %u but was %u src=0x%px offset=%u\n",
			__func__, zram->compressor, size, zhdr->size, src, offset);
		print_hex_dump_pages(src_page, zw->nr_pages, page_idx);
		BUG();
	}

	if (!dst_page) {
		kunmap_atomic(src);
		goto out;
	}

	dst = kmap_atomic(dst_page);
	zstrm = zcomp_stream_get(zram->comp);
	spanned = (offset + header_sz + size > PAGE_SIZE) ? true : false;
	if (spanned) {
		kunmap_atomic(src);
		if (size == PAGE_SIZE) {
			copy_to_buf(dst, src_page, page_idx, offset + header_sz, size);
			goto out_huge;
		}
		src = zstrm->tmpbuf;
		copy_to_buf(src, src_page, page_idx, offset + header_sz, size);
		src_decomp = src;
	} else {
		src_decomp = src + offset + header_sz;
	}
	ret = zcomp_decompress(zstrm, src_decomp, size, dst);
out_huge:
	zcomp_stream_put(zram->comp);
	if (ret) {
		pr_err("%s Decompression failed! err=%d, offset=%u, len=%u, vaddr=0x%px\n",
		       zram->compressor, ret, index, size, src_decomp);
		print_hex_dump_pages(src_page, zw->nr_pages, page_idx);
		panic("zram decomp failed");
	}
	kunmap_atomic(dst);
	if (!spanned)
		kunmap_atomic(src);
out_err:
	if (zw->bio_chain)
		bio_endio(zw->bio_chain);
out:
	bio_put(bio);

	if (!errno)
		zram_handle_remain(zram, src_page, blk_idx, zw->nr_pages);

	if (!dst_page)
		clear_bit(blk_to_chunk_idx(blk_idx), zram->read_req_bitmap);

	zram_dec_wb_table(zram, blk_idx + page_idx);
	free_zw_pages(zw);
	kfree(zw);
}

static void zram_comp_page_end_io(struct bio *bio)
{
	struct page *page = bio->bi_io_vec[0].bv_page;
	struct zram_wb_work *zw = (struct zram_wb_work *)page_private(page);

#ifdef CONFIG_ZRAM_PERF_STAT
	zram_perf_io_end(zw, READ);
#endif
	INIT_WORK(&zw->work, zram_handle_comp_page);
	schedule_work(&zw->work);
}

static int read_comp_from_bdev(struct zram *zram, struct bio_vec *bvec,
			unsigned long handle, struct bio *parent)
{
	struct zram_wb_work *zw;
	struct bio *bio;
	unsigned long blk_idx = handle >> IDX_SHIFT;
	int i, nr_pages = 1;

	if (is_ppr_idx(zram, blk_idx)) {
		blk_idx &= ZWBS_ALIGN_MASK;
		nr_pages = NR_ZWBS;
	}
	bio = bio_alloc(zram->bdev, nr_pages, REQ_OP_READ, GFP_NOIO);
	if (!bio)
		return -ENOMEM;

	zw = kzalloc(sizeof(struct zram_wb_work), GFP_NOIO);
	if (!zw) {
		bio_put(bio);
		return -ENOMEM;
	}
	zw->nr_pages = nr_pages;
	if (alloc_zw_pages(zw)) {
		kfree(zw);
		bio_put(bio);
		return -ENOMEM;
	}
	zw->dst_page = bvec ? bvec->bv_page : NULL;
	zw->zram = zram;
	zw->bio = bio;
	zw->handle = handle;
	set_page_private(zw->src_page[0], (unsigned long)zw);

	bio->bi_end_io = zram_comp_page_end_io;
	bio->bi_iter.bi_sector = blk_idx * (PAGE_SIZE >> 9);
	for (i = 0; i < nr_pages; i++)
		bio_add_page(bio, zw->src_page[i], PAGE_SIZE, 0);

	if (parent) {
		zw->bio_chain = bio_alloc(zram->bdev, 1, REQ_OP_READ, GFP_NOIO);
		if (!zw->bio_chain) {
			free_zw_pages(zw);
			kfree(zw);
			bio_put(bio);
			return -ENOMEM;
		}
		zw->bio_chain->bi_opf = parent->bi_opf;
		bio_chain(zw->bio_chain, parent);
	}

#ifdef CONFIG_ZRAM_PERF_STAT
	zram_perf_io_start(zw, READ);
#endif
	submit_bio(bio);
	return 1;
}

static int read_from_bdev(struct zram *zram, struct bio_vec *bvec,
			unsigned long handle, struct bio *parent)
{
	unsigned long blk_idx = handle >> IDX_SHIFT;
	unsigned int size = handle & (PAGE_SIZE - 1);

	atomic64_inc(&zram->stats.bd_reads);

	if (!size && !is_ppr_idx(zram, blk_idx))
		return read_from_bdev_async(zram, bvec, blk_idx, parent);
	else
		return read_comp_from_bdev(zram, bvec, handle, parent);
}
#else
struct zram_work {
	struct work_struct work;
	struct zram *zram;
	unsigned long entry;
	struct bio *bio;
	struct bio_vec bvec;
};

#if PAGE_SIZE != 4096
static void zram_sync_read(struct work_struct *work)
{
	struct zram_work *zw = container_of(work, struct zram_work, work);
	struct zram *zram = zw->zram;
	unsigned long entry = zw->entry;
	struct bio *bio = zw->bio;

	read_from_bdev_async(zram, &zw->bvec, entry, bio);
}

/*
 * Block layer want one ->submit_bio to be active at a time, so if we use
 * chained IO with parent IO in same context, it's a deadlock. To avoid that,
 * use a worker thread context.
 */
static int read_from_bdev_sync(struct zram *zram, struct bio_vec *bvec,
				unsigned long entry, struct bio *bio)
{
	struct zram_work work;

	work.bvec = *bvec;
	work.zram = zram;
	work.entry = entry;
	work.bio = bio;

	INIT_WORK_ONSTACK(&work.work, zram_sync_read);
	queue_work(system_unbound_wq, &work.work);
	flush_work(&work.work);
	destroy_work_on_stack(&work.work);

	return 1;
}
#else
static int read_from_bdev_sync(struct zram *zram, struct bio_vec *bvec,
				unsigned long entry, struct bio *bio)
{
	WARN_ON(1);
	return -EIO;
}
#endif

static int read_from_bdev(struct zram *zram, struct bio_vec *bvec,
			unsigned long entry, struct bio *parent, bool sync)
{
	atomic64_inc(&zram->stats.bd_reads);
	if (sync)
		return read_from_bdev_sync(zram, bvec, entry, parent);
	else
		return read_from_bdev_async(zram, bvec, entry, parent);
}
#endif
#else
static inline void reset_bdev(struct zram *zram) {};
static int read_from_bdev(struct zram *zram, struct bio_vec *bvec,
			unsigned long entry, struct bio *parent, bool sync)
{
	return -EIO;
}

static void free_block_bdev(struct zram *zram, unsigned long blk_idx) {};
#endif

#ifdef CONFIG_ZRAM_MEMORY_TRACKING

static struct dentry *zram_debugfs_root;

static void zram_debugfs_create(void)
{
	zram_debugfs_root = debugfs_create_dir("zram", NULL);
}

static void zram_debugfs_destroy(void)
{
	debugfs_remove_recursive(zram_debugfs_root);
}

static void zram_accessed(struct zram *zram, u32 index)
{
	zram_clear_flag(zram, index, ZRAM_IDLE);
	zram->table[index].ac_time = ktime_get_boottime();
}

static ssize_t read_block_state(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	char *kbuf;
	ssize_t index, written = 0;
	struct zram *zram = file->private_data;
	unsigned long nr_pages = zram->disksize >> PAGE_SHIFT;
	struct timespec64 ts;

	kbuf = kvmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	down_read(&zram->init_lock);
	if (!init_done(zram)) {
		up_read(&zram->init_lock);
		kvfree(kbuf);
		return -EINVAL;
	}

	for (index = *ppos; index < nr_pages; index++) {
		int copied;

		zram_slot_lock(zram, index);
		if (!zram_allocated(zram, index))
			goto next;

		ts = ktime_to_timespec64(zram->table[index].ac_time);
		copied = snprintf(kbuf + written, count,
			"%12zd %12lld.%06lu %c%c%c%c\n",
			index, (s64)ts.tv_sec,
			ts.tv_nsec / NSEC_PER_USEC,
			zram_test_flag(zram, index, ZRAM_SAME) ? 's' : '.',
			zram_test_flag(zram, index, ZRAM_WB) ? 'w' : '.',
			zram_test_flag(zram, index, ZRAM_HUGE) ? 'h' : '.',
			zram_test_flag(zram, index, ZRAM_IDLE) ? 'i' : '.');

		if (count <= copied) {
			zram_slot_unlock(zram, index);
			break;
		}
		written += copied;
		count -= copied;
next:
		zram_slot_unlock(zram, index);
		*ppos += 1;
	}

	up_read(&zram->init_lock);
	if (copy_to_user(buf, kbuf, written))
		written = -EFAULT;
	kvfree(kbuf);

	return written;
}

static const struct file_operations proc_zram_block_state_op = {
	.open = simple_open,
	.read = read_block_state,
	.llseek = default_llseek,
};

static void zram_debugfs_register(struct zram *zram)
{
	if (!zram_debugfs_root)
		return;

	zram->debugfs_dir = debugfs_create_dir(zram->disk->disk_name,
						zram_debugfs_root);
	debugfs_create_file("block_state", 0400, zram->debugfs_dir,
				zram, &proc_zram_block_state_op);
}

static void zram_debugfs_unregister(struct zram *zram)
{
	debugfs_remove_recursive(zram->debugfs_dir);
}
#else
static void zram_debugfs_create(void) {};
static void zram_debugfs_destroy(void) {};
static void zram_accessed(struct zram *zram, u32 index)
{
	zram_clear_flag(zram, index, ZRAM_IDLE);
};
static void zram_debugfs_register(struct zram *zram) {};
static void zram_debugfs_unregister(struct zram *zram) {};
#endif

/*
 * We switched to per-cpu streams and this attr is not needed anymore.
 * However, we will keep it around for some time, because:
 * a) we may revert per-cpu streams in the future
 * b) it's visible to user space and we need to follow our 2 years
 *    retirement rule; but we already have a number of 'soon to be
 *    altered' attrs, so max_comp_streams need to wait for the next
 *    layoff cycle.
 */
static ssize_t max_comp_streams_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", num_online_cpus());
}

static ssize_t max_comp_streams_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	return len;
}

static ssize_t comp_algorithm_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	size_t sz;
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	sz = zcomp_available_show(zram->compressor, buf);
	up_read(&zram->init_lock);

	return sz;
}

static ssize_t comp_algorithm_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);
	char compressor[ARRAY_SIZE(zram->compressor)];
	size_t sz;

	strscpy(compressor, buf, sizeof(compressor));
	/* ignore trailing newline */
	sz = strlen(compressor);
	if (sz > 0 && compressor[sz - 1] == '\n')
		compressor[sz - 1] = 0x00;

	if (!zcomp_available_algorithm(compressor))
		return -EINVAL;

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		up_write(&zram->init_lock);
		pr_info("Can't change algorithm for initialized device\n");
		return -EBUSY;
	}

	strcpy(zram->compressor, compressor);
	up_write(&zram->init_lock);
	return len;
}

static ssize_t compact_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);

	down_read(&zram->init_lock);
	if (!init_done(zram)) {
		up_read(&zram->init_lock);
		return -EINVAL;
	}

	zs_compact(zram->mem_pool);
	up_read(&zram->init_lock);

	return len;
}

static ssize_t io_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE,
			"%8llu %8llu %8llu %8llu\n",
			(u64)atomic64_read(&zram->stats.failed_reads),
			(u64)atomic64_read(&zram->stats.failed_writes),
			(u64)atomic64_read(&zram->stats.invalid_io),
			(u64)atomic64_read(&zram->stats.notify_free));
	up_read(&zram->init_lock);

	return ret;
}

static ssize_t mm_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	struct zs_pool_stats pool_stats;
	u64 orig_size, mem_used = 0;
	long max_used;
	ssize_t ret;

	memset(&pool_stats, 0x00, sizeof(struct zs_pool_stats));

	down_read(&zram->init_lock);
	if (init_done(zram)) {
		mem_used = zs_get_total_pages(zram->mem_pool);
		zs_pool_stats(zram->mem_pool, &pool_stats);
	}

	orig_size = atomic64_read(&zram->stats.pages_stored);
	max_used = atomic_long_read(&zram->stats.max_used_pages);

	ret = scnprintf(buf, PAGE_SIZE,
			"%8llu %8llu %8llu %8lu %8ld %8llu %8lu %8llu %8llu\n",
			orig_size << PAGE_SHIFT,
			(u64)atomic64_read(&zram->stats.compr_data_size),
			mem_used << PAGE_SHIFT,
			zram->limit_pages << PAGE_SHIFT,
			max_used << PAGE_SHIFT,
			(u64)atomic64_read(&zram->stats.same_pages),
			atomic_long_read(&pool_stats.pages_compacted),
			(u64)atomic64_read(&zram->stats.huge_pages),
			(u64)atomic64_read(&zram->stats.huge_pages_since));
	up_read(&zram->init_lock);

	return ret;
}

#ifdef CONFIG_ZRAM_WRITEBACK
#define FOUR_K(x) ((x) * (1 << (PAGE_SHIFT - 12)))
#ifdef CONFIG_ZRAM_RAMPLUS
static ssize_t bd_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE,
		"%8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu "
		"%8llu %8llu %8llu %8llu %8llu %8llu %8llu %8llu\n",
			FOUR_K((u64)atomic64_read(&zram->stats.bd_expire)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_count)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_reads)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_writes)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_objcnt)),
			(u64)(atomic64_read(&zram->stats.bd_size) >> PAGE_SHIFT),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_max_count)),
			(u64)(atomic64_read(&zram->stats.bd_max_size) >> PAGE_SHIFT),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_ppr_count)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_ppr_reads)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_ppr_writes)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_ppr_objcnt)),
			(u64)(atomic64_read(&zram->stats.bd_ppr_size) >> PAGE_SHIFT),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_ppr_max_count)),
			(u64)(atomic64_read(&zram->stats.bd_ppr_max_size) >> PAGE_SHIFT),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_objreads)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_objwrites)));
	up_read(&zram->init_lock);

	return ret;
}

static ssize_t bd_stat_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	struct zram *zram = dev_to_zram(dev);

	zram_reset_stats(zram);
	return len;
}
#else
static ssize_t bd_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE,
		"%8llu %8llu %8llu\n",
			FOUR_K((u64)atomic64_read(&zram->stats.bd_count)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_reads)),
			FOUR_K((u64)atomic64_read(&zram->stats.bd_writes)));
	up_read(&zram->init_lock);

	return ret;
}
#endif
#endif

static ssize_t debug_stat_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int version = 1;
	struct zram *zram = dev_to_zram(dev);
	ssize_t ret;

	down_read(&zram->init_lock);
	ret = scnprintf(buf, PAGE_SIZE,
			"version: %d\n%8llu %8llu\n",
			version,
			(u64)atomic64_read(&zram->stats.writestall),
			(u64)atomic64_read(&zram->stats.miss_free));
	up_read(&zram->init_lock);

	return ret;
}

static DEVICE_ATTR_RO(io_stat);
static DEVICE_ATTR_RO(mm_stat);
#ifdef CONFIG_ZRAM_WRITEBACK
#ifdef CONFIG_ZRAM_RAMPLUS
static DEVICE_ATTR_RW(bd_stat);
#else
static DEVICE_ATTR_RO(bd_stat);
#endif
#endif
static DEVICE_ATTR_RO(debug_stat);

static void zram_meta_free(struct zram *zram, u64 disksize)
{
	size_t num_pages = disksize >> PAGE_SHIFT;
	size_t index;

	/* Free all pages that are still in this zram device */
	for (index = 0; index < num_pages; index++)
		zram_free_page(zram, index);

	zs_destroy_pool(zram->mem_pool);
	vfree(zram->table);
}

static bool zram_meta_alloc(struct zram *zram, u64 disksize)
{
	size_t num_pages;

	num_pages = disksize >> PAGE_SHIFT;
	zram->table = vzalloc(array_size(num_pages, sizeof(*zram->table)));
	if (!zram->table)
		return false;

	zram->mem_pool = zs_create_pool(zram->disk->disk_name);
	if (!zram->mem_pool) {
		vfree(zram->table);
		return false;
	}

	if (!huge_class_size)
		huge_class_size = zs_huge_class_size(zram->mem_pool);
	return true;
}

/*
 * To protect concurrent access to the same index entry,
 * caller should hold this table index entry's bit_spinlock to
 * indicate this index entry is accessing.
 */
static void zram_free_page(struct zram *zram, size_t index)
{
	unsigned long handle;
#ifdef CONFIG_ZRAM_RAMPLUS
	int size;
#endif

#ifdef CONFIG_ZRAM_MEMORY_TRACKING
	zram->table[index].ac_time = 0;
#endif
	if (zram_test_flag(zram, index, ZRAM_IDLE))
		zram_clear_flag(zram, index, ZRAM_IDLE);

	if (zram_test_flag(zram, index, ZRAM_HUGE)) {
		zram_clear_flag(zram, index, ZRAM_HUGE);
		atomic64_dec(&zram->stats.huge_pages);
	}

	if (zram_test_flag(zram, index, ZRAM_WB)) {
		zram_clear_flag(zram, index, ZRAM_WB);
#ifdef CONFIG_ZRAM_RAMPLUS
		handle = zram_get_element(zram, index);
		size = handle & (PAGE_SIZE - 1) ? : PAGE_SIZE;
		atomic64_sub(size, &zram->stats.bd_size);
		if (zram_test_flag(zram, index, ZRAM_PPR))
			atomic64_sub(size, &zram->stats.bd_ppr_size);
		if (zram_test_flag(zram, index, ZRAM_EXPIRE)) {
			zram_clear_flag(zram, index, ZRAM_EXPIRE);
			atomic64_dec(&zram->stats.bd_expire);
		}
		free_block_bdev(zram, handle >> IDX_SHIFT);
#else
		free_block_bdev(zram, zram_get_element(zram, index));
#endif
		goto out;
	}

	/*
	 * No memory is allocated for same element filled pages.
	 * Simply clear same page flag.
	 */
	if (zram_test_flag(zram, index, ZRAM_SAME)) {
		zram_clear_flag(zram, index, ZRAM_SAME);
		atomic64_dec(&zram->stats.same_pages);
		goto out;
	}

	handle = zram_get_handle(zram, index);
	if (!handle)
		return;

	zs_free(zram->mem_pool, handle);

	atomic64_sub(zram_get_obj_size(zram, index),
			&zram->stats.compr_data_size);
out:
	atomic64_dec(&zram->stats.pages_stored);
	zram_set_handle(zram, index, 0);
	zram_set_obj_size(zram, index, 0);
#ifdef CONFIG_ZRAM_RAMPLUS
	if (zram_test_flag(zram, index, ZRAM_PPR))
		zram_clear_flag(zram, index, ZRAM_PPR);
	zram_reset_lru_entry(zram, index);
#endif
	WARN_ON_ONCE(zram->table[index].flags &
		~(1UL << ZRAM_LOCK | 1UL << ZRAM_UNDER_WB));
}

static int __zram_bvec_read(struct zram *zram, struct page *page, u32 index,
				struct bio *bio, bool partial_io)
{
	struct zcomp_strm *zstrm;
	unsigned long handle;
	unsigned int size;
	void *src, *dst;
	int ret;
#ifdef CONFIG_ZRAM_RAMPLUS
	unsigned long blk_idx;
#endif

	zram_slot_lock(zram, index);
	if (zram_test_flag(zram, index, ZRAM_WB)) {
		struct bio_vec bvec;

		/* A null bio means rw_page was used, we must fallback to bio */
		if (!bio) {
			zram_slot_unlock(zram, index);
			return -EOPNOTSUPP;
		}

		bvec.bv_page = page;
		bvec.bv_len = PAGE_SIZE;
		bvec.bv_offset = 0;
#ifdef CONFIG_ZRAM_RAMPLUS
		if (zram_test_flag(zram, index, ZRAM_PPR))
			atomic64_inc(&zram->stats.bd_ppr_reads);
		if (!zram_test_flag(zram, index, ZRAM_EXPIRE)) {
			zram_set_flag(zram, index, ZRAM_EXPIRE);
			atomic64_inc(&zram->stats.bd_expire);
		}
		handle = zram_get_element(zram, index);
		blk_idx = handle >> IDX_SHIFT;
		zram_inc_wb_table(zram, blk_idx);
		zram_slot_unlock(zram, index);
		ret = read_from_bdev(zram, &bvec, handle, bio);
		if (ret < 0)
			zram_dec_wb_table(zram, blk_idx);
		return ret;
#else
		zram_slot_unlock(zram, index);
		return read_from_bdev(zram, &bvec,
				zram_get_element(zram, index),
				bio, partial_io);
#endif
	}

	handle = zram_get_handle(zram, index);
	if (!handle || zram_test_flag(zram, index, ZRAM_SAME)) {
		unsigned long value;
		void *mem;

		value = handle ? zram_get_element(zram, index) : 0;
		mem = kmap_atomic(page);
		zram_fill_page(mem, PAGE_SIZE, value);
		kunmap_atomic(mem);
		zram_slot_unlock(zram, index);
		return 0;
	}

	size = zram_get_obj_size(zram, index);

	if (size != PAGE_SIZE)
		zstrm = zcomp_stream_get(zram->comp);

	src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
	if (size == PAGE_SIZE) {
		dst = kmap_atomic(page);
		memcpy(dst, src, PAGE_SIZE);
		kunmap_atomic(dst);
		ret = 0;
	} else {
		dst = kmap_atomic(page);
		ret = zcomp_decompress(zstrm, src, size, dst);
		kunmap_atomic(dst);
		zcomp_stream_put(zram->comp);
	}

	/* Should NEVER happen. panic() if it does. */
	if (unlikely(ret)) {
		pr_err("%s Decompression failed! err=%d, index=%u, len=%u, vaddr=0x%px\n",
		       zram->compressor, ret, index, size, src);
		print_hex_dump_fmt(src, size);
		panic("zram decomp failed");
	}

	zs_unmap_object(zram->mem_pool, handle);
	zram_slot_unlock(zram, index);

	return ret;
}

static int zram_bvec_read(struct zram *zram, struct bio_vec *bvec,
				u32 index, int offset, struct bio *bio)
{
	int ret;
	struct page *page;

	page = bvec->bv_page;
	if (is_partial_io(bvec)) {
		/* Use a temporary buffer to decompress the page */
		page = alloc_page(GFP_NOIO|__GFP_HIGHMEM);
		if (!page)
			return -ENOMEM;
	}

	ret = __zram_bvec_read(zram, page, index, bio, is_partial_io(bvec));
	if (unlikely(ret))
		goto out;

	if (is_partial_io(bvec)) {
		void *src = kmap_atomic(page);

		memcpy_to_bvec(bvec, src + offset);
		kunmap_atomic(src);
	}
out:
	if (is_partial_io(bvec))
		__free_page(page);

	return ret;
}

static int __zram_bvec_write(struct zram *zram, struct bio_vec *bvec,
				u32 index, struct bio *bio)
{
	int ret = 0;
	unsigned long alloced_pages;
	unsigned long handle = -ENOMEM;
	unsigned int comp_len = 0;
	void *src, *dst, *mem;
	struct zcomp_strm *zstrm;
	struct page *page = bvec->bv_page;
	unsigned long element = 0;
	enum zram_pageflags flags = 0;

	mem = kmap_atomic(page);
	if (page_same_filled(mem, &element)) {
		kunmap_atomic(mem);
		/* Free memory associated with this sector now. */
		flags = ZRAM_SAME;
		atomic64_inc(&zram->stats.same_pages);
		goto out;
	}
	kunmap_atomic(mem);

compress_again:
	zstrm = zcomp_stream_get(zram->comp);
	src = kmap_atomic(page);
	ret = zcomp_compress(zstrm, src, &comp_len);
	kunmap_atomic(src);

	if (unlikely(ret)) {
		zcomp_stream_put(zram->comp);
		pr_err("Compression failed! err=%d\n", ret);
		zs_free(zram->mem_pool, handle);
		return ret;
	}

	if (comp_len >= huge_class_size)
		comp_len = PAGE_SIZE;
	/*
	 * handle allocation has 2 paths:
	 * a) fast path is executed with preemption disabled (for
	 *  per-cpu streams) and has __GFP_DIRECT_RECLAIM bit clear,
	 *  since we can't sleep;
	 * b) slow path enables preemption and attempts to allocate
	 *  the page with __GFP_DIRECT_RECLAIM bit set. we have to
	 *  put per-cpu compression stream and, thus, to re-do
	 *  the compression once handle is allocated.
	 *
	 * if we have a 'non-null' handle here then we are coming
	 * from the slow path and handle has already been allocated.
	 */
	if (IS_ERR((void *)handle))
		handle = zs_malloc(zram->mem_pool, comp_len,
				__GFP_KSWAPD_RECLAIM |
				__GFP_NOWARN |
				__GFP_HIGHMEM |
				__GFP_MOVABLE |
				__GFP_CMA);
	if (IS_ERR((void *)handle)) {
		zcomp_stream_put(zram->comp);
		atomic64_inc(&zram->stats.writestall);
		handle = zs_malloc(zram->mem_pool, comp_len,
				GFP_NOIO | __GFP_HIGHMEM |
				__GFP_MOVABLE | __GFP_CMA);
		if (IS_ERR((void *)handle))
			return PTR_ERR((void *)handle);

		if (comp_len != PAGE_SIZE)
			goto compress_again;
		/*
		 * If the page is not compressible, you need to acquire the
		 * lock and execute the code below. The zcomp_stream_get()
		 * call is needed to disable the cpu hotplug and grab the
		 * zstrm buffer back. It is necessary that the dereferencing
		 * of the zstrm variable below occurs correctly.
		 */
		zstrm = zcomp_stream_get(zram->comp);
	}

	alloced_pages = zs_get_total_pages(zram->mem_pool);
	update_used_max(zram, alloced_pages);

	if (zram->limit_pages && alloced_pages > zram->limit_pages) {
		zcomp_stream_put(zram->comp);
		zs_free(zram->mem_pool, handle);
		return -ENOMEM;
	}

	dst = zs_map_object(zram->mem_pool, handle, ZS_MM_WO);

	src = zstrm->buffer;
	if (comp_len == PAGE_SIZE)
		src = kmap_atomic(page);
	memcpy(dst, src, comp_len);
	if (comp_len == PAGE_SIZE)
		kunmap_atomic(src);

	zcomp_stream_put(zram->comp);
	zs_unmap_object(zram->mem_pool, handle);
	atomic64_add(comp_len, &zram->stats.compr_data_size);
out:
	/*
	 * Free memory associated with this sector
	 * before overwriting unused sectors.
	 */
	zram_slot_lock(zram, index);
	zram_free_page(zram, index);

	if (comp_len == PAGE_SIZE) {
		zram_set_flag(zram, index, ZRAM_HUGE);
		atomic64_inc(&zram->stats.huge_pages);
		atomic64_inc(&zram->stats.huge_pages_since);
	}

	if (flags) {
		zram_set_flag(zram, index, flags);
		zram_set_element(zram, index, element);
	} else {
		zram_set_handle(zram, index, handle);
		zram_set_obj_size(zram, index, comp_len);
#ifdef CONFIG_ZRAM_RAMPLUS
		zram_entry_move_list(zram, NULL, index);
		try_wakeup_zram_lru_writebackd(zram);
#endif
	}
	zram_slot_unlock(zram, index);

	/* Update stats */
	atomic64_inc(&zram->stats.pages_stored);
	return ret;
}

static int zram_bvec_write(struct zram *zram, struct bio_vec *bvec,
				u32 index, int offset, struct bio *bio)
{
	int ret;
	struct page *page = NULL;
	struct bio_vec vec;

	vec = *bvec;
	if (is_partial_io(bvec)) {
		void *dst;
		/*
		 * This is a partial IO. We need to read the full page
		 * before to write the changes.
		 */
		page = alloc_page(GFP_NOIO|__GFP_HIGHMEM);
		if (!page)
			return -ENOMEM;

		ret = __zram_bvec_read(zram, page, index, bio, true);
		if (ret)
			goto out;

		dst = kmap_atomic(page);
		memcpy_from_bvec(dst + offset, bvec);
		kunmap_atomic(dst);

		vec.bv_page = page;
		vec.bv_len = PAGE_SIZE;
		vec.bv_offset = 0;
	}

	ret = __zram_bvec_write(zram, &vec, index, bio);
out:
	if (is_partial_io(bvec))
		__free_page(page);
	return ret;
}

/*
 * zram_bio_discard - handler on discard request
 * @index: physical block index in PAGE_SIZE units
 * @offset: byte offset within physical block
 */
static void zram_bio_discard(struct zram *zram, u32 index,
			     int offset, struct bio *bio)
{
	size_t n = bio->bi_iter.bi_size;

	/*
	 * zram manages data in physical block size units. Because logical block
	 * size isn't identical with physical block size on some arch, we
	 * could get a discard request pointing to a specific offset within a
	 * certain physical block.  Although we can handle this request by
	 * reading that physiclal block and decompressing and partially zeroing
	 * and re-compressing and then re-storing it, this isn't reasonable
	 * because our intent with a discard request is to save memory.  So
	 * skipping this logical block is appropriate here.
	 */
	if (offset) {
		if (n <= (PAGE_SIZE - offset))
			return;

		n -= (PAGE_SIZE - offset);
		index++;
	}

	while (n >= PAGE_SIZE) {
		zram_slot_lock(zram, index);
		zram_free_page(zram, index);
		zram_slot_unlock(zram, index);
		atomic64_inc(&zram->stats.notify_free);
		index++;
		n -= PAGE_SIZE;
	}
}

/*
 * Returns errno if it has some problem. Otherwise return 0 or 1.
 * Returns 0 if IO request was done synchronously
 * Returns 1 if IO request was successfully submitted.
 */
static int zram_bvec_rw(struct zram *zram, struct bio_vec *bvec, u32 index,
			int offset, enum req_op op, struct bio *bio)
{
	int ret;

	if (!op_is_write(op)) {
		atomic64_inc(&zram->stats.num_reads);
		ret = zram_bvec_read(zram, bvec, index, offset, bio);
		flush_dcache_page(bvec->bv_page);
	} else {
		atomic64_inc(&zram->stats.num_writes);
		ret = zram_bvec_write(zram, bvec, index, offset, bio);
	}

	zram_slot_lock(zram, index);
	zram_accessed(zram, index);
	zram_slot_unlock(zram, index);

	if (unlikely(ret < 0)) {
		if (!op_is_write(op))
			atomic64_inc(&zram->stats.failed_reads);
		else
			atomic64_inc(&zram->stats.failed_writes);
	}

	return ret;
}

static void __zram_make_request(struct zram *zram, struct bio *bio)
{
	int offset;
	u32 index;
	struct bio_vec bvec;
	struct bvec_iter iter;
	unsigned long start_time;

	index = bio->bi_iter.bi_sector >> SECTORS_PER_PAGE_SHIFT;
	offset = (bio->bi_iter.bi_sector &
		  (SECTORS_PER_PAGE - 1)) << SECTOR_SHIFT;

	switch (bio_op(bio)) {
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		zram_bio_discard(zram, index, offset, bio);
		bio_endio(bio);
		return;
	default:
		break;
	}

	start_time = bio_start_io_acct(bio);
	bio_for_each_segment(bvec, bio, iter) {
		struct bio_vec bv = bvec;
		unsigned int unwritten = bvec.bv_len;

		do {
			bv.bv_len = min_t(unsigned int, PAGE_SIZE - offset,
							unwritten);
			if (zram_bvec_rw(zram, &bv, index, offset,
					 bio_op(bio), bio) < 0) {
				bio->bi_status = BLK_STS_IOERR;
				break;
			}

			bv.bv_offset += bv.bv_len;
			unwritten -= bv.bv_len;

			update_position(&index, &offset, &bv);
		} while (unwritten);
	}
	bio_end_io_acct(bio, start_time);
	bio_endio(bio);
}

/*
 * Handler function for all zram I/O requests.
 */
static void zram_submit_bio(struct bio *bio)
{
	struct zram *zram = bio->bi_bdev->bd_disk->private_data;

	if (!valid_io_request(zram, bio->bi_iter.bi_sector,
					bio->bi_iter.bi_size)) {
		atomic64_inc(&zram->stats.invalid_io);
		bio_io_error(bio);
		return;
	}

	__zram_make_request(zram, bio);
}

static void zram_slot_free_notify(struct block_device *bdev,
				unsigned long index)
{
	struct zram *zram;

	zram = bdev->bd_disk->private_data;

	atomic64_inc(&zram->stats.notify_free);
	if (!zram_slot_trylock(zram, index)) {
		atomic64_inc(&zram->stats.miss_free);
		return;
	}

	zram_free_page(zram, index);
	zram_slot_unlock(zram, index);
}

static int zram_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, enum req_op op)
{
	int offset, ret;
	u32 index;
	struct zram *zram;
	struct bio_vec bv;
	unsigned long start_time;

	if (PageTransHuge(page))
		return -ENOTSUPP;
	zram = bdev->bd_disk->private_data;

	if (!valid_io_request(zram, sector, PAGE_SIZE)) {
		atomic64_inc(&zram->stats.invalid_io);
		ret = -EINVAL;
		goto out;
	}

	index = sector >> SECTORS_PER_PAGE_SHIFT;
	offset = (sector & (SECTORS_PER_PAGE - 1)) << SECTOR_SHIFT;

	bv.bv_page = page;
	bv.bv_len = PAGE_SIZE;
	bv.bv_offset = 0;

	start_time = bdev_start_io_acct(bdev->bd_disk->part0,
			SECTORS_PER_PAGE, op, jiffies);
	ret = zram_bvec_rw(zram, &bv, index, offset, op, NULL);
	bdev_end_io_acct(bdev->bd_disk->part0, op, start_time);
out:
	/*
	 * If I/O fails, just return error(ie, non-zero) without
	 * calling page_endio.
	 * It causes resubmit the I/O with bio request by upper functions
	 * of rw_page(e.g., swap_readpage, __swap_writepage) and
	 * bio->bi_end_io does things to handle the error
	 * (e.g., SetPageError, set_page_dirty and extra works).
	 */
	if (unlikely(ret < 0))
		return ret;

	switch (ret) {
	case 0:
		page_endio(page, op_is_write(op), 0);
		break;
	case 1:
		ret = 0;
		break;
	default:
		WARN_ON(1);
	}
	return ret;
}

static void zram_reset_device(struct zram *zram)
{
	down_write(&zram->init_lock);

	zram->limit_pages = 0;

	if (!init_done(zram)) {
		up_write(&zram->init_lock);
		return;
	}

	set_capacity_and_notify(zram->disk, 0);
	part_stat_set_all(zram->disk->part0, 0);

	/* I/O operation under all of CPU are done so let's free */
	zram_meta_free(zram, zram->disksize);
	zram->disksize = 0;
	memset(&zram->stats, 0, sizeof(zram->stats));
	zcomp_destroy(zram->comp);
	zram->comp = NULL;
	reset_bdev(zram);

	up_write(&zram->init_lock);
}

static ssize_t disksize_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 disksize;
	struct zcomp *comp;
	struct zram *zram = dev_to_zram(dev);
	int err;
	disksize = memparse(buf, NULL);
	if (!disksize)
		return -EINVAL;

	down_write(&zram->init_lock);
	if (init_done(zram)) {
		pr_info("Cannot change disksize for initialized device\n");
		err = -EBUSY;
		goto out_unlock;
	}

	disksize = PAGE_ALIGN(disksize);
	if (!zram_meta_alloc(zram, disksize)) {
		err = -ENOMEM;
		goto out_unlock;
	}

	comp = zcomp_create(zram->compressor);
	if (IS_ERR(comp)) {
		pr_err("Cannot initialise %s compressing backend\n",
				zram->compressor);
		err = PTR_ERR(comp);
		goto out_free_meta;
	}
#ifdef CONFIG_ZRAM_RAMPLUS
	init_lru_writeback(zram, disksize);

	if (!strncmp(zram->compressor, "lzo-rle", 7))
		is_lzorle = true;
#endif

	zram->comp = comp;
	zram->disksize = disksize;
	set_capacity_and_notify(zram->disk, zram->disksize >> SECTOR_SHIFT);
	up_write(&zram->init_lock);

	return len;

out_free_meta:
	zram_meta_free(zram, disksize);
out_unlock:
	up_write(&zram->init_lock);
	return err;
}

static ssize_t reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int ret;
	unsigned short do_reset;
	struct zram *zram;
	struct gendisk *disk;

	ret = kstrtou16(buf, 10, &do_reset);
	if (ret)
		return ret;

	if (!do_reset)
		return -EINVAL;

	zram = dev_to_zram(dev);
	disk = zram->disk;

	mutex_lock(&disk->open_mutex);
	/* Do not reset an active device or claimed device */
	if (disk_openers(disk) || zram->claim) {
		mutex_unlock(&disk->open_mutex);
		return -EBUSY;
	}

	/* From now on, anyone can't open /dev/zram[0-9] */
	zram->claim = true;
	mutex_unlock(&disk->open_mutex);

	/* Make sure all the pending I/O are finished */
	sync_blockdev(disk->part0);
	zram_reset_device(zram);

	mutex_lock(&disk->open_mutex);
	zram->claim = false;
	mutex_unlock(&disk->open_mutex);

	return len;
}

static int zram_open(struct block_device *bdev, fmode_t mode)
{
	int ret = 0;
	struct zram *zram;

	WARN_ON(!mutex_is_locked(&bdev->bd_disk->open_mutex));

	zram = bdev->bd_disk->private_data;
	/* zram was claimed to reset so open request fails */
	if (zram->claim)
		ret = -EBUSY;

	return ret;
}

static const struct block_device_operations zram_devops = {
	.open = zram_open,
	.submit_bio = zram_submit_bio,
	.swap_slot_free_notify = zram_slot_free_notify,
	.rw_page = zram_rw_page,
	.owner = THIS_MODULE
};

static DEVICE_ATTR_WO(compact);
static DEVICE_ATTR_RW(disksize);
static DEVICE_ATTR_RO(initstate);
static DEVICE_ATTR_WO(reset);
static DEVICE_ATTR_WO(mem_limit);
static DEVICE_ATTR_WO(mem_used_max);
static DEVICE_ATTR_WO(idle);
static DEVICE_ATTR_RW(max_comp_streams);
static DEVICE_ATTR_RW(comp_algorithm);
#ifdef CONFIG_ZRAM_WRITEBACK
static DEVICE_ATTR_RW(backing_dev);
static DEVICE_ATTR_WO(writeback);
static DEVICE_ATTR_RW(writeback_limit);
static DEVICE_ATTR_RW(writeback_limit_enable);
#endif

static struct attribute *zram_disk_attrs[] = {
	&dev_attr_disksize.attr,
	&dev_attr_initstate.attr,
	&dev_attr_reset.attr,
	&dev_attr_compact.attr,
	&dev_attr_mem_limit.attr,
	&dev_attr_mem_used_max.attr,
	&dev_attr_idle.attr,
	&dev_attr_max_comp_streams.attr,
	&dev_attr_comp_algorithm.attr,
#ifdef CONFIG_ZRAM_WRITEBACK
	&dev_attr_backing_dev.attr,
	&dev_attr_writeback.attr,
	&dev_attr_writeback_limit.attr,
	&dev_attr_writeback_limit_enable.attr,
#endif
	&dev_attr_io_stat.attr,
	&dev_attr_mm_stat.attr,
#ifdef CONFIG_ZRAM_WRITEBACK
	&dev_attr_bd_stat.attr,
#endif
	&dev_attr_debug_stat.attr,
#ifdef CONFIG_ZRAM_PERF_STAT
	&dev_attr_perf_stat.attr,
#endif
	NULL,
};

ATTRIBUTE_GROUPS(zram_disk);

static long get_zram_total_kbytes(struct zram *zram)
{
	unsigned long kbytes;

	if (!zram || !down_read_trylock(&zram->init_lock))
		return 0;

	if (!init_done(zram) || !zram->mem_pool)
		kbytes = 0;
	else
		kbytes = zs_get_total_pages(zram->mem_pool) << (PAGE_SHIFT - 10);
	up_read(&zram->init_lock);

	return kbytes;
}

static void zram_show_mem(void *data, unsigned int filter, nodemask_t *nodemask)
{
	struct zram *zram = (struct zram *)data;
	long total_kbytes = get_zram_total_kbytes(zram);

	if (total_kbytes == 0)
		return;

	pr_info("%s: %ld kB\n", zram->disk->disk_name, total_kbytes);
}

static void zram_meminfo(void *data, struct seq_file *m)
{
	struct zram *zram = (struct zram *)data;
	long total_kbytes = get_zram_total_kbytes(zram);

	if (total_kbytes == 0)
		return;

	show_val_meminfo(m, zram->disk->disk_name, total_kbytes);
}

#ifdef CONFIG_ZRAM_RAMPLUS
#ifdef CONFIG_ZRAM_LRU_WRITEBACK
static void zram_entry_move_list(struct zram *zram,
			struct list_head *list, u32 index)
{
	struct zram_ramplus *ramplus = &zram->ramplus[LRU_WRITEBACK];
	unsigned long flags;

	/* if list is NULL, add/move entry to lru list */
	if (!list) {
		list = &ramplus->list;
		zram_set_flag(zram, index, ZRAM_LRU);
		atomic64_inc(&zram->stats.lru_pages);
	}
	spin_lock_irqsave(&ramplus->lock, flags);
	if (list_empty(&zram->table[index].list))
		list_add_tail(&zram->table[index].list, list);
	else
		list_move_tail(&zram->table[index].list, list);
	spin_unlock_irqrestore(&ramplus->lock, flags);
}

static void zram_reset_lru_entry(struct zram *zram, u32 index)
{
	struct zram_ramplus *ramplus = &zram->ramplus[LRU_WRITEBACK];
	unsigned long flags;

	if (zram_test_flag(zram, index, ZRAM_LRU)) {
		zram_clear_flag(zram, index, ZRAM_LRU);
		atomic64_dec(&zram->stats.lru_pages);
	}
	spin_lock_irqsave(&ramplus->lock, flags);
	if (!list_empty(&zram->table[index].list))
		list_del_init(&zram->table[index].list);
	spin_unlock_irqrestore(&ramplus->lock, flags);
}

static u32 entry_to_index(struct zram *zram, struct zram_table_entry *entry)
{
	if ((unsigned long)entry < (unsigned long)zram->table)
		return zram->disksize >> PAGE_SHIFT;
	return (u32)(((unsigned long)entry - (unsigned long)zram->table) /
			sizeof(struct zram_table_entry));
}

static int zram_balance_ratio;
module_param(zram_balance_ratio, int, 0644);

#define ZRAM_LRU_WRITEBACK_INTERVAL ((10)*(HZ))
static bool zram_should_writeback(struct zram *zram,
				unsigned long pages, bool trigger)
{
	unsigned long stored = atomic64_read(&zram->stats.lru_pages);
	long writtenback = max_t(long, 0,
			atomic64_read(&zram->stats.bd_objcnt) -
			atomic64_read(&zram->stats.bd_ppr_objcnt) -
			atomic64_read(&zram->stats.bd_expire));
	unsigned long min_stored_byte;
	int writtenback_ratio = stored ? (writtenback * 100) / stored : 0;
	int min_writtenback_ratio = zram_balance_ratio;
	int margin = max_t(int, 1, zram_balance_ratio / 10);
	int max_pages = CONFIG_ZRAM_LRU_WRITEBACK_LIMIT;
	static unsigned long time_stamp;
	bool ret = true;

	/* avoid app launch time */
	if (is_app_launch)
		return false;

	/* stop thread when writtenback enough */
	if (pages > max_pages)
		return false;

	/* do not trigger again before time interval */
	if (trigger && time_is_after_jiffies(time_stamp))
		return false;

	if (trigger)
		min_writtenback_ratio -= margin;
	else
		min_writtenback_ratio += margin;
	if (min_writtenback_ratio < writtenback_ratio)
		ret = false;

	if (zram->disksize / 4 > SZ_1G)
		min_stored_byte = SZ_1G;
	else
		min_stored_byte = zram->disksize / 4;

	if ((stored << PAGE_SHIFT) < min_stored_byte)
		ret = false;

	if (trigger && ret == true)
		time_stamp = jiffies + ZRAM_LRU_WRITEBACK_INTERVAL;

	return ret;
}

static void try_wakeup_zram_lru_writebackd(struct zram *zram)
{
	unsigned long bd_count;

	if (zram_wb_available(zram)) {
		bd_count = atomic64_read(&zram->stats.bd_count);
		/* wakeup zram_lru_writebackd with enough free blocks */
		if (zram->nr_pages - bd_count < NR_ZWBS)
			return;

		wake_up(&zram->ramplus[LRU_WRITEBACK].wait);
	}
}

static int zram_lru_writebackd(void *p)
{
	struct zram *zram = (struct zram *)p;
	struct zram_ramplus *ramplus = &zram->ramplus[LRU_WRITEBACK];
	struct zram_table_entry *entry;
	struct zram_writeback_buffer *buf = NULL;
	struct list_head *list = &ramplus->list;
	unsigned long flags;
	u32 index;

	set_freezable();

	while (!kthread_should_stop()) {
		unsigned long nr_pages = 0;
		bool should_stop = false;

		wait_event_freezable(ramplus->wait,
				zram_should_writeback(zram, 0, true) ||
				kthread_should_stop());
		spin_lock_irqsave(&ramplus->lock, flags);
		while (!list_empty(list) && !should_stop) {
			if (try_to_freeze() || kthread_should_stop())
				break;
			if (!zram_wb_available(zram))
				break;
			entry = list_first_entry(list, struct zram_table_entry, list);
			list_del_init(&entry->list);
			spin_unlock_irqrestore(&ramplus->lock, flags);
			index = entry_to_index(zram, entry);
			zram_slot_lock(zram, index);
			if (!zram_allocated(zram, index) ||
					!zram_test_flag(zram, index, ZRAM_LRU) ||
					zram_test_flag(zram, index, ZRAM_IDLE) ||
					zram_test_flag(zram, index, ZRAM_WB) ||
					zram_test_flag(zram, index, ZRAM_UNDER_WB)) {
				zram_slot_unlock(zram, index);
			} else {
				zram_set_flag(zram, index, ZRAM_IDLE);
				zram_slot_unlock(zram, index);
				if (zram_writeback_index(zram, index, &buf, false))
					should_stop = true;
			}
			if (!zram_should_writeback(zram, ++nr_pages, false))
				should_stop = true;
			spin_lock_irqsave(&ramplus->lock, flags);
		}
		spin_unlock_irqrestore(&ramplus->lock, flags);
	}
	free_writeback_buffer(buf);

	return 0;
}

static void init_lru_writeback(struct zram *zram, u64 disksize)
{
	struct sched_param param = { .sched_priority = 0 };
	int i;

	sched_setscheduler(zram->ramplus[LRU_WRITEBACK].task, SCHED_IDLE, &param);
	zram->nr_lru_pages = (zram->nr_pages * LRU_LIMIT_RATIO / 10) & ZWBS_ALIGN_MASK;

	for (i = 0; i < disksize >> PAGE_SHIFT; i++)
		INIT_LIST_HEAD(&zram->table[i].list);
}
#endif

static void zram_count_entry_type(void *data, swp_entry_t swpent,
				unsigned long *writeback,
				unsigned long *same, unsigned long *huge)
{
	struct zram *zram = (struct zram *)data;
	u32 index = swp_offset(swpent);

	if (index >= (zram->disksize >> PAGE_SHIFT))
		return;

	zram_slot_lock(zram, index);
	if (zram_allocated(zram, index)) {
		if (zram_test_flag(zram, index, ZRAM_WB))
			(*writeback) += PAGE_SIZE;
		else if (zram_test_flag(zram, index, ZRAM_SAME))
			(*same) += PAGE_SIZE;
		else if (zram_test_flag(zram, index, ZRAM_HUGE))
			(*huge) += PAGE_SIZE;
	}
	zram_slot_unlock(zram, index);
}

static void zram_show_entry_type(void *data, struct seq_file *m,
				unsigned long writeback,
				unsigned long same, unsigned long huge)
{
	char str[100];
	char *p = str;

	p += sprintf(p, "Writeback:      %8lu kB\n", writeback >> 10);
	p += sprintf(p, "Same:           %8lu kB\n", same >> 10);
	p += sprintf(p, "Huge:           %8lu kB\n", huge >> 10);
	seq_puts(m, str);
}

static void zram_fill_request_pool(struct work_struct *work)
{
	struct zram_ramplus *ramplus = container_of(work, struct zram_ramplus, work);
	struct zram_request *req;

	while (atomic_read(&ramplus->nr) < MAX_NR_POOL) {
		req = kvzalloc(sizeof(struct zram_request), GFP_KERNEL);
		if (!req)
			break;
		INIT_LIST_HEAD(&req->list);
		spin_lock(&ramplus->lock);
		list_add_tail(&req->list, &ramplus->list);
		spin_unlock(&ramplus->lock);
		atomic_inc(&ramplus->nr);
	}
	ramplus->running = false;
	pr_info("%s %d\n", __func__, atomic_read(&ramplus->nr));
}

static void zram_add_to_request(struct zram *zram, u32 index, int type)
{
	struct zram_ramplus *ramplus = &zram->ramplus[type];
	struct zram_ramplus *pool = &zram->ramplus[POOL];
	struct zram_request *req = NULL;

	spin_lock(&ramplus->lock);
	if (!list_empty(&ramplus->list)) {
		req = list_last_entry(&ramplus->list, struct zram_request, list);
		if (req->last < MAX_REQ_IDX) {
			spin_unlock(&ramplus->lock);
			goto out;
		}
	}
	spin_unlock(&ramplus->lock);

	/* schedule work to fill request pool */
	if (atomic_read(&pool->nr) < MIN_NR_POOL && !pool->running) {
		pool->running = true;
		schedule_work(&pool->work);
	}

	/* try to get one from req table pool */
	spin_lock(&pool->lock);
	req = list_first_entry_or_null(&pool->list, struct zram_request, list);
	if (!req) {
		spin_unlock(&pool->lock);
		/* try alloc directly if we don't have one in pool */
		req = kvzalloc(sizeof(struct zram_request), GFP_NOWAIT);
		if (!req) {
			pr_info("%s failed to alloc request\n", __func__);
			return;
		}
		INIT_LIST_HEAD(&req->list);
	} else {
		list_del_init(&req->list);
		spin_unlock(&pool->lock);
		atomic_dec(&pool->nr);
	}
	spin_lock(&ramplus->lock);
	list_add_tail(&req->list, &ramplus->list);
	spin_unlock(&ramplus->lock);
out:
	req->index[req->last++] = index;
	if (type == PREFETCH) {
		atomic_inc(&ramplus->nr);
		wake_up(&ramplus->wait);
	}
}

static void zram_flush_writeback_buffer(struct zram *zram,
					struct zram_writeback_buffer *buf)
{
	if (buf && buf->zwbs[0]->cnt) {
		/* mark end of pages */
		for (; buf->idx < NR_ZWBS; buf->idx++)
			mark_end_of_page(buf->zwbs[buf->idx]);
		zram_writeback_page(zram, buf, true);
	} else {
		/* free empty buf */
		free_writeback_buffer(buf);
	}
}

static void zram_writeback_work(struct work_struct *work)
{
	struct zram_wb_work *zw = container_of(work, struct zram_wb_work, work);
	struct zram *zram = zw->zram;
	struct zram_writeback_buffer *buf = NULL;
	struct zram_request *req;
	struct list_head *list = &zw->list;
	u32 index;

	while (!list_empty(list)) {
		req = list_first_entry(list, struct zram_request, list);
		while (req->first < req->last) {
			index = req->index[req->first++];
			zram_writeback_index(zram, index, &buf, true);
		}
		list_del_init(&req->list);
		kvfree(req);
	}
	zram_flush_writeback_buffer(zram, buf);
	kfree(zw);
}

static void zram_process_madvise_end(void *data, int behavior, ssize_t *ret)
{
	struct zram *zram = (struct zram *)data;
	struct zram_ramplus *ramplus;
	struct zram_wb_work *zw;

	if (behavior != MADV_WRITEBACK)
		return;

	ramplus = &zram->ramplus[WRITEBACK];
	if (list_empty(&ramplus->list))
		return;

	zw = kzalloc(sizeof(struct zram_wb_work), GFP_NOWAIT);
	if (!zw) {
		*ret = -ENOMEM;
		return;
	}
	zw->zram = zram;
	INIT_LIST_HEAD(&zw->list);
	spin_lock(&ramplus->lock);
	list_splice_init(&ramplus->list, &zw->list);
	spin_unlock(&ramplus->lock);
	INIT_WORK(&zw->work, zram_writeback_work);
	schedule_work(&zw->work);
}

static void zram_request_writeback(void *data, swp_entry_t swpent, int swapcount)
{
	struct zram *zram = (struct zram *)data;
	u32 index = swp_offset(swpent);

	if (swapcount > 1)
		return;
	if (!zram_wb_available(zram))
		return;
	if (index >= (zram->disksize >> PAGE_SHIFT))
		return;
	if (!zram_slot_trylock(zram, index))
		return;
	if (!zram_allocated(zram, index) ||
			zram_test_flag(zram, index, ZRAM_IDLE) ||
			zram_test_flag(zram, index, ZRAM_WB) ||
			zram_test_flag(zram, index, ZRAM_SAME) ||
			zram_test_flag(zram, index, ZRAM_UNDER_WB)) {
		zram_slot_unlock(zram, index);
		return;
	}
	zram_reset_lru_entry(zram, index);
	zram_set_flag(zram, index, ZRAM_IDLE);
	zram_slot_unlock(zram, index);
	zram_add_to_request(zram, index, WRITEBACK);
}

static void zram_prefetch_entry(struct zram *zram, u32 index)
{
	unsigned long handle;
	unsigned long blk_idx;
	unsigned long chunk_idx;

	zram_slot_lock(zram, index);
	if (!zram_allocated(zram, index) ||
			!zram_test_flag(zram, index, ZRAM_WB) ||
			!zram_test_flag(zram, index, ZRAM_PPR)) {
		zram_slot_unlock(zram, index);
		return;
	}
	handle = zram_get_element(zram, index);
	blk_idx = handle >> IDX_SHIFT;
	chunk_idx = blk_to_chunk_idx(blk_idx);
	if (test_and_set_bit(chunk_idx, zram->read_req_bitmap)) {
		zram_slot_unlock(zram, index);
		return;
	}
	zram_inc_wb_table(zram, blk_idx);
	zram_slot_unlock(zram, index);
	if (read_from_bdev(zram, NULL, handle, NULL) < 0)
		zram_dec_wb_table(zram, blk_idx);
	atomic64_inc(&zram->stats.bd_ppr_reads);
}

static void zram_request_prefetch(void *data, swp_entry_t swpent)
{
	struct zram *zram = (struct zram *)data;
	u32 index = swp_offset(swpent);

	if (index >= (zram->disksize >> PAGE_SHIFT))
		return;
	if (!zram_slot_trylock(zram, index))
		return;
	if (!zram_allocated(zram, index) ||
			!zram_test_flag(zram, index, ZRAM_WB) ||
			!zram_test_flag(zram, index, ZRAM_PPR)) {
		zram_slot_unlock(zram, index);
		return;
	}
	zram_slot_unlock(zram, index);
	zram_add_to_request(zram, index, PREFETCH);
}

static int zram_prefetchd(void *p)
{
	struct zram *zram = (struct zram *)p;
	struct zram_ramplus *ramplus = &zram->ramplus[PREFETCH];
	struct zram_request *req;
	struct list_head *list = &ramplus->list;
	u32 index;

	set_freezable();

	while (!kthread_should_stop()) {
		wait_event_freezable(ramplus->wait,
				atomic_read(&ramplus->nr) ||
				kthread_should_stop());
		while (!list_empty(list) && atomic_read(&ramplus->nr)) {
			if (try_to_freeze() || kthread_should_stop())
				break;
			req = list_first_entry(list, struct zram_request, list);
			while (req->first < req->last) {
				index = req->index[req->first++];
				zram_prefetch_entry(zram, index);
				atomic_dec(&ramplus->nr);
			}
			if (req->first == MAX_REQ_IDX) {
				spin_lock(&ramplus->lock);
				list_del_init(&req->list);
				spin_unlock(&ramplus->lock);
				kvfree(req);
			}
		}
	}
	return 0;
}

static void deinit_ramplus(struct zram *zram)
{
	unsigned long flags;
	u16 *wb_table = zram->wb_table;
	int i;

	for (i = 0; i < NR_RAMPLUS_TYPES; i++) {
		if (!IS_ERR_OR_NULL(zram->ramplus[i].task)) {
			kthread_stop(zram->ramplus[i].task);
			zram->ramplus[i].task = NULL;
		}
	}
	if (zram->read_req_bitmap) {
		kvfree(zram->read_req_bitmap);
		zram->read_req_bitmap = NULL;
	}
	if (zram->chunk_bitmap) {
		kvfree(zram->chunk_bitmap);
		zram->chunk_bitmap = NULL;
	}
	if (zram->blk_bitmap) {
		kvfree(zram->blk_bitmap);
		zram->blk_bitmap = NULL;
	}
	spin_lock_irqsave(&zram->wb_table_lock, flags);
	zram->wb_table = NULL;
	spin_unlock_irqrestore(&zram->wb_table_lock, flags);

	kvfree(wb_table);
	unregister_trace_android_vh_smaps_pte_entry(zram_count_entry_type, zram);
	unregister_trace_android_vh_show_smap(zram_show_entry_type, zram);
	unregister_trace_android_vh_madvise_swapin_walk_pmd_entry(zram_request_prefetch, zram);
	unregister_trace_android_vh_madvise_pageout_swap_entry(zram_request_writeback, zram);
	unregister_trace_android_vh_process_madvise_end(zram_process_madvise_end, zram);
}

static int init_ramplus(struct zram *zram, unsigned long nr_pages)
{
	const char * const name[] = {
		"prefetchd",
#ifdef CONFIG_ZRAM_LRU_WRITEBACK
		"lru_writebackd"
#endif
	};
	int (*threadfn[])(void *data) = {
		zram_prefetchd,
#ifdef CONFIG_ZRAM_LRU_WRITEBACK
		zram_lru_writebackd
#endif
	};
	int size = BITS_TO_LONGS(nr_pages) * sizeof(long);
	int i;

	/* backing dev should be large enough */
	if (size < max_t(int, NR_FALLOC_PAGES, NR_ZWBS))
		return -EINVAL;

	zram->wb_table = kvzalloc(sizeof(*zram->wb_table) * nr_pages, GFP_KERNEL);
	if (!zram->wb_table)
		goto out;
	zram->blk_bitmap = kvzalloc(size / NR_FALLOC_PAGES, GFP_KERNEL);
	if (!zram->blk_bitmap)
		goto out;
	zram->chunk_bitmap = kvzalloc(size / NR_ZWBS, GFP_KERNEL);
	if (!zram->chunk_bitmap)
		goto out;
	zram->read_req_bitmap = kvzalloc(size / NR_ZWBS, GFP_KERNEL);
	if (!zram->read_req_bitmap)
		goto out;
	for (i = 0; i < NR_RAMPLUS_TYPES; i++) {
		INIT_LIST_HEAD(&zram->ramplus[i].list);
		spin_lock_init(&zram->ramplus[i].lock);
		if (i < WRITEBACK) {
			init_waitqueue_head(&zram->ramplus[i].wait);
			zram->ramplus[i].task = kthread_run(threadfn[i], zram,
					"%s_%s", zram->disk->disk_name, name[i]);
			if (IS_ERR(zram->ramplus[i].task))
				goto out;
		}
	}
	INIT_WORK(&zram->ramplus[POOL].work, zram_fill_request_pool);
	zram->wb_limit_enable = true;
	register_trace_android_vh_smaps_pte_entry(zram_count_entry_type, zram);
	register_trace_android_vh_show_smap(zram_show_entry_type, zram);
	register_trace_android_vh_madvise_swapin_walk_pmd_entry(zram_request_prefetch, zram);
	register_trace_android_vh_madvise_pageout_swap_entry(zram_request_writeback, zram);
	register_trace_android_vh_process_madvise_end(zram_process_madvise_end, zram);

	return 0;
out:
	deinit_ramplus(zram);
	return -ENOMEM;
}

static ssize_t app_launch_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	int ret;

	ret = is_app_launch ? 1 : 0;
	return sprintf(buf, "%d\n", is_app_launch);
}

static ssize_t app_launch_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	struct zram *zram;
	unsigned short val = 0;
	int ret;

	ret = kstrtou16(buf, 10, &val);
	if (ret)
		return ret;

	is_app_launch = val ? true : false;
	zram = idr_find(&zram_index_idr, 0);
#ifdef CONFIG_ZRAM_RAMPLUS
	if (!is_app_launch && zram)
		try_wakeup_zram_lru_writebackd(zram);
#endif
	return count;
}

static struct kobj_attribute app_launch_attr = __ATTR_RW(app_launch);

static struct attribute *zram_ramplus_attrs[] = {
	&app_launch_attr.attr,
	NULL,
};

ATTRIBUTE_GROUPS(zram_ramplus);
#endif

/*
 * Allocate and initialize new zram device. the function returns
 * '>= 0' device_id upon success, and negative value otherwise.
 */
static int zram_add(void)
{
	struct zram *zram;
	int ret, device_id;

	zram = kzalloc(sizeof(struct zram), GFP_KERNEL);
	if (!zram)
		return -ENOMEM;

	ret = idr_alloc(&zram_index_idr, zram, 0, 0, GFP_KERNEL);
	if (ret < 0)
		goto out_free_dev;
	device_id = ret;

	init_rwsem(&zram->init_lock);
#ifdef CONFIG_ZRAM_WRITEBACK
	spin_lock_init(&zram->wb_limit_lock);
#endif
#ifdef CONFIG_ZRAM_RAMPLUS
	spin_lock_init(&zram->wb_table_lock);
	spin_lock_init(&zram->bitmap_lock);
	mutex_init(&zram->blk_bitmap_lock);
#endif

	/* gendisk structure */
	zram->disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!zram->disk) {
		pr_err("Error allocating disk structure for device %d\n",
			device_id);
		ret = -ENOMEM;
		goto out_free_idr;
	}

	zram->disk->major = zram_major;
	zram->disk->first_minor = device_id;
	zram->disk->minors = 1;
	zram->disk->flags |= GENHD_FL_NO_PART;
	zram->disk->fops = &zram_devops;
	zram->disk->private_data = zram;
	snprintf(zram->disk->disk_name, 16, "zram%d", device_id);

	/* Actual capacity set using syfs (/sys/block/zram<id>/disksize */
	set_capacity(zram->disk, 0);
	/* zram devices sort of resembles non-rotational disks */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, zram->disk->queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, zram->disk->queue);

	/*
	 * To ensure that we always get PAGE_SIZE aligned
	 * and n*PAGE_SIZED sized I/O requests.
	 */
	blk_queue_physical_block_size(zram->disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(zram->disk->queue,
					ZRAM_LOGICAL_BLOCK_SIZE);
	blk_queue_io_min(zram->disk->queue, PAGE_SIZE);
	blk_queue_io_opt(zram->disk->queue, PAGE_SIZE);
	zram->disk->queue->limits.discard_granularity = PAGE_SIZE;
	blk_queue_max_discard_sectors(zram->disk->queue, UINT_MAX);

	/*
	 * zram_bio_discard() will clear all logical blocks if logical block
	 * size is identical with physical block size(PAGE_SIZE). But if it is
	 * different, we will skip discarding some parts of logical blocks in
	 * the part of the request range which isn't aligned to physical block
	 * size.  So we can't ensure that all discarded logical blocks are
	 * zeroed.
	 */
	if (ZRAM_LOGICAL_BLOCK_SIZE == PAGE_SIZE)
		blk_queue_max_write_zeroes_sectors(zram->disk->queue, UINT_MAX);

	blk_queue_flag_set(QUEUE_FLAG_STABLE_WRITES, zram->disk->queue);
	ret = device_add_disk(NULL, zram->disk, zram_disk_groups);
	if (ret)
		goto out_cleanup_disk;

	strscpy(zram->compressor, default_compressor, sizeof(zram->compressor));

	zram_debugfs_register(zram);
	pr_info("Added device: %s\n", zram->disk->disk_name);
	register_trace_android_vh_show_mem(zram_show_mem, zram);
	register_trace_android_vh_meminfo_proc_show(zram_meminfo, zram);

	return device_id;

out_cleanup_disk:
	put_disk(zram->disk);
out_free_idr:
	idr_remove(&zram_index_idr, device_id);
out_free_dev:
	kfree(zram);
	return ret;
}

static int zram_remove(struct zram *zram)
{
	bool claimed;

	mutex_lock(&zram->disk->open_mutex);
	if (disk_openers(zram->disk)) {
		mutex_unlock(&zram->disk->open_mutex);
		return -EBUSY;
	}

	unregister_trace_android_vh_show_mem(zram_show_mem, zram);
	unregister_trace_android_vh_meminfo_proc_show(zram_meminfo, zram);

	claimed = zram->claim;
	if (!claimed)
		zram->claim = true;
	mutex_unlock(&zram->disk->open_mutex);

	zram_debugfs_unregister(zram);

	if (claimed) {
		/*
		 * If we were claimed by reset_store(), del_gendisk() will
		 * wait until reset_store() is done, so nothing need to do.
		 */
		;
	} else {
		/* Make sure all the pending I/O are finished */
		sync_blockdev(zram->disk->part0);
		zram_reset_device(zram);
	}

	pr_info("Removed device: %s\n", zram->disk->disk_name);

	del_gendisk(zram->disk);

	/* del_gendisk drains pending reset_store */
	WARN_ON_ONCE(claimed && zram->claim);

	/*
	 * disksize_store() may be called in between zram_reset_device()
	 * and del_gendisk(), so run the last reset to avoid leaking
	 * anything allocated with disksize_store()
	 */
	zram_reset_device(zram);

	put_disk(zram->disk);
	kfree(zram);
	return 0;
}

/* zram-control sysfs attributes */

/*
 * NOTE: hot_add attribute is not the usual read-only sysfs attribute. In a
 * sense that reading from this file does alter the state of your system -- it
 * creates a new un-initialized zram device and returns back this device's
 * device_id (or an error code if it fails to create a new device).
 */
static ssize_t hot_add_show(struct class *class,
			struct class_attribute *attr,
			char *buf)
{
	int ret;

	mutex_lock(&zram_index_mutex);
	ret = zram_add();
	mutex_unlock(&zram_index_mutex);

	if (ret < 0)
		return ret;
	return scnprintf(buf, PAGE_SIZE, "%d\n", ret);
}
static struct class_attribute class_attr_hot_add =
	__ATTR(hot_add, 0400, hot_add_show, NULL);

static ssize_t hot_remove_store(struct class *class,
			struct class_attribute *attr,
			const char *buf,
			size_t count)
{
	struct zram *zram;
	int ret, dev_id;

	/* dev_id is gendisk->first_minor, which is `int' */
	ret = kstrtoint(buf, 10, &dev_id);
	if (ret)
		return ret;
	if (dev_id < 0)
		return -EINVAL;

	mutex_lock(&zram_index_mutex);

	zram = idr_find(&zram_index_idr, dev_id);
	if (zram) {
		ret = zram_remove(zram);
		if (!ret)
			idr_remove(&zram_index_idr, dev_id);
	} else {
		ret = -ENODEV;
	}

	mutex_unlock(&zram_index_mutex);
	return ret ? ret : count;
}
static CLASS_ATTR_WO(hot_remove);

static struct attribute *zram_control_class_attrs[] = {
	&class_attr_hot_add.attr,
	&class_attr_hot_remove.attr,
	NULL,
};
ATTRIBUTE_GROUPS(zram_control_class);

static struct class zram_control_class = {
	.name		= "zram-control",
	.owner		= THIS_MODULE,
	.class_groups	= zram_control_class_groups,
};

static int zram_remove_cb(int id, void *ptr, void *data)
{
	WARN_ON_ONCE(zram_remove(ptr));
	return 0;
}

static void destroy_devices(void)
{
#ifdef CONFIG_ZRAM_RAMPLUS
	if (zram_kobject) {
		sysfs_remove_groups(zram_kobject, zram_ramplus_groups);
		kobject_put(zram_kobject);
	}
#endif
	class_unregister(&zram_control_class);
	idr_for_each(&zram_index_idr, &zram_remove_cb, NULL);
	zram_debugfs_destroy();
	idr_destroy(&zram_index_idr);
	unregister_blkdev(zram_major, "zram");
	cpuhp_remove_multi_state(CPUHP_ZCOMP_PREPARE);
}

static int __init zram_init(void)
{
	int ret;

	BUILD_BUG_ON(__NR_ZRAM_PAGEFLAGS > BITS_PER_LONG);

	ret = cpuhp_setup_state_multi(CPUHP_ZCOMP_PREPARE, "block/zram:prepare",
				      zcomp_cpu_up_prepare, zcomp_cpu_dead);
	if (ret < 0)
		return ret;

	ret = class_register(&zram_control_class);
	if (ret) {
		pr_err("Unable to register zram-control class\n");
		cpuhp_remove_multi_state(CPUHP_ZCOMP_PREPARE);
		return ret;
	}

	zram_debugfs_create();
	zram_major = register_blkdev(0, "zram");
	if (zram_major <= 0) {
		pr_err("Unable to get major number\n");
		class_unregister(&zram_control_class);
		cpuhp_remove_multi_state(CPUHP_ZCOMP_PREPARE);
		return -EBUSY;
	}
#ifdef CONFIG_ZRAM_RAMPLUS
	zram_kobject = kobject_create_and_add("zram", kernel_kobj);
	if (!zram_kobject) {
		pr_err("Unable to create kobject\n");
		ret = -EINVAL;
		goto out_error;
	}
	ret = sysfs_create_groups(zram_kobject, zram_ramplus_groups);
	if (ret) {
		pr_err("Unable to create sysfs group\n");
		kobject_put(zram_kobject);
		goto out_error;
	}
#endif

	while (num_devices != 0) {
		mutex_lock(&zram_index_mutex);
		ret = zram_add();
		mutex_unlock(&zram_index_mutex);
		if (ret < 0)
			goto out_error;
		num_devices--;
	}

	return 0;

out_error:
	destroy_devices();
	return ret;
}

static void __exit zram_exit(void)
{
	destroy_devices();
}

module_init(zram_init);
module_exit(zram_exit);

module_param(num_devices, uint, 0);
MODULE_PARM_DESC(num_devices, "Number of pre-created zram devices");

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
MODULE_DESCRIPTION("Compressed RAM Block Device");
