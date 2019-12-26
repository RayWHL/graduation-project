/**
 * 1：vm_area_struct 第一行加 unsigned long find_page_count;  //number of map uncount (done)
 * 2：vm_area_struct 初始化count赋值0，初始化应该在mmap函数中   (undo)
 * 3：主要修改filemap_fault函数 (done)
 * 
 * TODO : mmap中初始化， cgroup接口文件的修改（commit中
 * 
 * filemap_fault入口增加printk  __do_fault 增加printk
 * 
 * mem_charge page不能在lru中，替换成更底层的try_charge
 * 
 * printk(KERN_INFO "The cuurent process commond ： \"%s\"  the pid ：%d\n", current->comm, current->pid);  
 * 
 * 
 * DONE ： 
 * 1 /include/linux/mm_types.h  struct vm_area_struct（L292）增添到L328
 * 2 /mm/filemap.c filemap_fault（L2497）增添到L2520 L2509
 * 3 添加了printk_count 和 printk相关
 * 4 /mm/memory.c  handle_pte_fault 添加printk  L3805
 * 5 /mm/memory.c do_fault L3582  do_read_fault 3473  __do_fault 3065
 * 
 * 5.4.2
 * /include/linux/mm_types.h struct vm_area_strucst L292
 * /mm/filemap.c  filemap_map_pages L2623	 主要修改（5.4.2）
 * 
 * todo:
 * 初始化
 * 
 * 
 * 第二个进程do_read_fault 然后 do_fault_around, 调用vma ops的map_pages函数（指向filemap_map_pages)
 * 
 * 
 * 
 * 2019/12/14
 * read write也存在page cahce，考虑修改pagecache_get_page函数
 * 1、do_fault_around采用中的man_page采用遍历查找page cache
 * 2、__do_fault中的filemap_fault采用find_get_page实现
 * 3、read
 * 4、write
 * 
 * 
 * 2019/12/24
 * mmap的读先do_falut_around（调用了 filemap_map_pages)，然后调用 filemap_fault
 * 		写只调用filemap_fault
 * 
 * 基于linux5.4.6 从新设计解决方案
 * 1、file结构增加计数位 详见read.c中 源码位置：/include/linux/fs.h	L935
 * 2、filemap_map_pages (do_fault_around调用) 详见modify.c  源码位置/mm/filemap.c L2623
 * 3、filemap_fault 详见modify.c	源码位置 /mm/filemap.c L2497
 * 4、generic_file_buffered_read  详见read.c  源码位置 /mm/filemap.c L2009
 * 5、grab_cache_page_write_begin 详见write.c	源码位置 /mm/filemap.c	L3246
 * 6、do_sys_open 初始化 详见open.c  源码位置 /fs/open.c L1082
 * 总共享计数怎么获得? inode/dentry计数 open增加了哪个计数?
 * A:总引用计数在dentry的引用计数（file结构数）
 * 
 **/

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 * https://blog.csdn.net/SweeNeil/article/details/83902755
 * https://baike.baidu.com/item/vm_area_struct%E7%BB%93%E6%9E%84%E4%BD%93/23620940?fr=aladdin
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */

	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next, *vm_prev;

	struct rb_node vm_rb;

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */

	struct mm_struct *vm_mm;	/* The address space we belong to. 指向mm_struct结构 */
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	unsigned long vm_flags;		/* Flags, see mm.h. */

	/*
	 * For areas with an address Z and backing store,
	 * linkage into the address_space->i_mmap interval tree.
	 */
	struct {
		struct rb_node rb;
		unsigned long rb_subtree_last;
	} shared;


    /*
     * 该缺页中断时，计数其它进程引入的page数，用于调整cgroup计数
     */
    atomic_t find_page_count;


	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	struct list_head anon_vma_chain; /* Serialized by mmap_sem &
					  * page_table_lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	const struct vm_operations_struct *vm_ops;  //一般为generic_file_vm_ops

	/* Information about our backing store: */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units */
	struct file * vm_file;		/* File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */

#ifdef CONFIG_SWAP
	atomic_long_t swap_readahead_info;
#endif
#ifndef CONFIG_MMU
	struct vm_region *vm_region;	/* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
} __randomize_layout;









/**
 * 真正的.fault指向的函数
 * filemap_fault - read in file data for page fault handling
 * @vmf:	struct vm_fault containing details of the fault
 *
 * filemap_fault() is invoked via the vma operations vector for a
 * mapped memory region to read in file data during a page fault.
 *
 * The goto's are kind of ugly, but this streamlines the normal case of having
 * it in the page cache, and handles the special cases reasonably without
 * having a lot of duplicated code.
 *
 * vma->vm_mm->mmap_sem must be held on entry.
 *
 * If our return value has VM_FAULT_RETRY set, it's because the mmap_sem
 * may be dropped before doing I/O or by lock_page_maybe_drop_mmap().
 *
 * If our return value does not have VM_FAULT_RETRY set, the mmap_sem
 * has not been released.
 *
 * We never return with VM_FAULT_RETRY and a bit from VM_FAULT_ERROR set.
 *
 * Return: bitwise-OR of %VM_FAULT_ codes.
 */
vm_fault_t filemap_fault(struct vm_fault *vmf)
{
	int error;
	struct file *file = vmf->vma->vm_file;
	struct file *fpin = NULL;
	struct address_space *mapping = file->f_mapping;
	struct file_ra_state *ra = &file->f_ra;
	struct inode *inode = mapping->host;
	pgoff_t offset = vmf->pgoff;
	pgoff_t max_off;
	struct page *page;
	vm_fault_t ret = 0;



	max_off = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	if (unlikely(offset >= max_off))
		return VM_FAULT_SIGBUS;

	/*
	 * Do we have something in the page cache already?
	 */
	page = find_get_page(mapping, offset);		//在file的address_space中查找是否存在该page，找到会增加page的引用计数refcount
	if (likely(page) && !(vmf->flags & FAULT_FLAG_TRIED)) {



        if(page->mem_cgroup!=get_mem_cgroup_from_mm(current->mm)){
			//printk("%d: not same cgroup\n",current->pid);
            //首先对file中共享page计数加一
            //atomic_add(1,&(vmf->vma->find_page_count));
            atomic_add(1,&(file->find_page_count));

            //计数大于等于vma数量
            if(atomic_read(&(file->find_page_count))>=file->f_path.dentry->d_lockref.count || 
				atomic_read(&(file->find_page_count))<0){
                atomic_set(&(file->find_page_count),0); //count位置0 
                /*
                 * page所指mem_cgroup uncharge
                 * 当前进程的mem_cgroup charge
                 */
                // mem_cgroup_uncharge(page);
                // mem_cgroup_try_charge(page,current->mm,vmf->gfp_mask,&cgroup_temp,false);
                // mem_cgroup_commit_charge(page, cgroup_temp, false, false);
                //     //page->mem_cgroup=get_mem_cgroup_from_mm(current->mm);   //修改page所属mem_cgroup
				// 	page->mem_cgroup=cgroup_temp;

				// 	//message
				// 	atomic_add(1,&(vmf->vma->printk_count));
				// 	if(atomic_read(&(vmf->vma->printk_count))>=1000 || atomic_read(&(vmf->vma->printk_count))<0 )
				// 	{
				// 		atomic_set(&(vmf->vma->printk_count),0);
				// 		printk("there");
				// 	}

				printk("filemap_fault: pid %d  dentry_count %d \n",current->pid,file->f_path.dentry->d_lockref.count);

				//if(current->pid>2000)
				if (trylock_page(page))
				{
					mem_cgroup_uncharge(page);
                	mem_cgroup_try_charge(page,current->mm,vmf->gfp_mask,&cgroup_temp,false);
                	mem_cgroup_commit_charge(page, cgroup_temp, false, false);
					unlock_page(page);
				}
			}
		}






		/*
		 * We found the page, so try async readahead before
		 * waiting for the lock.
		 */
		fpin = do_async_mmap_readahead(vmf, page);		//预读
	} else if (!page) {
		/* No page in the page cache at all */
		count_vm_event(PGMAJFAULT);
		count_memcg_event_mm(vmf->vma->vm_mm, PGMAJFAULT);
		ret = VM_FAULT_MAJOR;
		fpin = do_sync_mmap_readahead(vmf);
retry_find:
		page = pagecache_get_page(mapping, offset,
					  FGP_CREAT|FGP_FOR_MMAP,
					  vmf->gfp_mask);		//FGP_CREAT用于在未找到page时创建一个新page
		if (!page) {
			if (fpin)
				goto out_retry;
			return vmf_error(-ENOMEM);
		}
	}

	if (!lock_page_maybe_drop_mmap(vmf, page, &fpin))
		goto out_retry;

	/* Did it get truncated? */
	if (unlikely(compound_head(page)->mapping != mapping)) {
		unlock_page(page);
		put_page(page);
		goto retry_find;
	}
	VM_BUG_ON_PAGE(page_to_pgoff(page) != offset, page);

	/*
	 * We have a locked page in the page cache, now we need to check
	 * that it's up-to-date. If not, it is going to be due to an error.
	 */
	if (unlikely(!PageUptodate(page)))
		goto page_not_uptodate;

	/*
	 * We've made it this far and we had to drop our mmap_sem, now is the
	 * time to return to the upper layer and have it re-find the vma and
	 * redo the fault.
	 */
	if (fpin) {
		unlock_page(page);
		goto out_retry;
	}

	/*
	 * Found the page and have a reference on it.
	 * We must recheck i_size under page lock.
	 */
	max_off = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	if (unlikely(offset >= max_off)) {
		unlock_page(page);
		put_page(page);
		return VM_FAULT_SIGBUS;
	}

	vmf->page = page;
	return ret | VM_FAULT_LOCKED;

page_not_uptodate:
	/*
	* Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 */
	ClearPageError(page);
	fpin = maybe_unlock_mmap_for_io(vmf, fpin);
	error = mapping->a_ops->readpage(file, page);
	if (!error) {
		wait_on_page_locked(page);
		if (!PageUptodate(page))
			error = -EIO;
	}
	if (fpin)
		goto out_retry;
	put_page(page);

	if (!error || error == AOP_TRUNCATED_PAGE)
		goto retry_find;

	/* Things didn't work out. Return zero to tell the mm layer so. */
	shrink_readahead_size_eio(file, ra);
	return VM_FAULT_SIGBUS;

out_retry:
	/*
	 * We dropped the mmap_sem, we need to return to the fault handler to
	 * re-find the vma and come back and find our hopefully still populated
	 * page.
	 */
	if (page)
		put_page(page);
	if (fpin)
		fput(fpin);
	return ret | VM_FAULT_RETRY;
}


/*
 * Asynchronous readahead happens when we find the page and PG_readahead,
 * so we want to possibly extend the readahead further.  We return the file that
 * was pinned if we have to drop the mmap_sem in order to do IO.
 * page为在page cache找到的page
 */
static struct file *do_async_mmap_readahead(struct vm_fault *vmf,
					    struct page *page)
{
	struct file *file = vmf->vma->vm_file;
	struct file_ra_state *ra = &file->f_ra;
	struct address_space *mapping = file->f_mapping;
	struct file *fpin = NULL;
	pgoff_t offset = vmf->pgoff;

	/* If we don't want any read-ahead, don't bother */
	if (vmf->vma->vm_flags & VM_RAND_READ)
		return fpin;
	if (ra->mmap_miss > 0)
		ra->mmap_miss--;
	if (PageReadahead(page)) {
		fpin = maybe_unlock_mmap_for_io(vmf, fpin);
		page_cache_async_readahead(mapping, ra, file,
					   page, offset, ra->ra_pages);
	}
	return fpin;
}


static vm_fault_t do_fault_around(struct vm_fault *vmf)
{
	unsigned long address = vmf->address, nr_pages, mask;
	pgoff_t start_pgoff = vmf->pgoff;
	pgoff_t end_pgoff;
	int off;
	vm_fault_t ret = 0;

	nr_pages = READ_ONCE(fault_around_bytes) >> PAGE_SHIFT;
	mask = ~(nr_pages * PAGE_SIZE - 1) & PAGE_MASK;

	vmf->address = max(address & mask, vmf->vma->vm_start);
	off = ((address - vmf->address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
	start_pgoff -= off;

	/*
	 *  end_pgoff is either the end of the page table, the end of
	 *  the vma or nr_pages from start_pgoff, depending what is nearest.
	 */
	end_pgoff = start_pgoff -
		((vmf->address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1)) +
		PTRS_PER_PTE - 1;
	end_pgoff = min3(end_pgoff, vma_pages(vmf->vma) + vmf->vma->vm_pgoff - 1,
			start_pgoff + nr_pages - 1);

	if (pmd_none(*vmf->pmd)) {
		vmf->prealloc_pte = pte_alloc_one(vmf->vma->vm_mm);
		if (!vmf->prealloc_pte)
			goto out;
		smp_wmb(); /* See comment in __pte_alloc() */
	}

	vmf->vma->vm_ops->map_pages(vmf, start_pgoff, end_pgoff);

	/* Huge page is mapped? Page fault is solved */
	if (pmd_trans_huge(*vmf->pmd)) {
		ret = VM_FAULT_NOPAGE;
		goto out;
	}

	/* ->map_pages() haven't done anything useful. Cold page cache? */
	if (!vmf->pte)
		goto out;

	/* check if the page fault is solved */
	vmf->pte -= (vmf->address >> PAGE_SHIFT) - (address >> PAGE_SHIFT);
	if (!pte_none(*vmf->pte))
		ret = VM_FAULT_NOPAGE;
	pte_unmap_unlock(vmf->pte, vmf->ptl);
out:
	vmf->address = address;
	vmf->pte = NULL;
	return ret;
}

/**
 * struct address_space - Contents of a cacheable, mappable object.
 * @host: Owner, either the inode or the block_device.
 * @i_pages: Cached pages.
 * @gfp_mask: Memory allocation flags to use for allocating pages.
 * @i_mmap_writable: Number of VM_SHARED mappings.
 * @nr_thps: Number of THPs in the pagecache (non-shmem only).
 * @i_mmap: Tree of private and shared mappings.
 * @i_mmap_rwsem: Protects @i_mmap and @i_mmap_writable.
 * @nrpages: Number of page entries, protected by the i_pages lock.
 * @nrexceptional: Shadow or DAX entries, protected by the i_pages lock.
 * @writeback_index: Writeback starts here.
 * @a_ops: Methods.
 * @flags: Error bits and flags (AS_*).
 * @wb_err: The most recent error which has occurred.
 * @private_lock: For use by the owner of the address_space.
 * @private_list: For use by the owner of the address_space.
 * @private_data: For use by the owner of the address_space.
 */
struct address_space {
	struct inode		*host;
	struct xarray		i_pages;
	gfp_t			gfp_mask;
	atomic_t		i_mmap_writable;
#ifdef CONFIG_READ_ONLY_THP_FOR_FS
	/* number of thp, only for non-shmem files */
	atomic_t		nr_thps;
#endif
	struct rb_root_cached	i_mmap;
	struct rw_semaphore	i_mmap_rwsem;
	unsigned long		nrpages;
	unsigned long		nrexceptional;
	pgoff_t			writeback_index;
	const struct address_space_operations *a_ops;
	unsigned long		flags;
	errseq_t		wb_err;
	spinlock_t		private_lock;
	struct list_head	private_list;
	void			*private_data;
} __attribute__((aligned(sizeof(long)))) __randomize_layout;


/**
 * handle_mm_fault前持有mm_sem
 * 
 **/

//vma操作函数 map_pages 指向的函数
void filemap_map_pages(struct vm_fault *vmf,
		pgoff_t start_pgoff, pgoff_t end_pgoff)
{
	struct file *file = vmf->vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	pgoff_t last_pgoff = start_pgoff;
	unsigned long max_idx;
	XA_STATE(xas, &mapping->i_pages, start_pgoff);  //初始化数组，初始索引为start，所有在page cache中的page
	struct page *page;

	rcu_read_lock();
	xas_for_each(&xas, page, end_pgoff) {  //遍历所有start到end的page
		if (xas_retry(&xas, page)) //无效下一个
			continue;
		if (xa_is_value(page))  //判断为值或指针
			goto next;

		/*
		 * Check for a locked page first, as a speculative
		 * reference may adversely influence page migration.
		 */
		if (PageLocked(page))
			goto next;
		if (!page_cache_get_speculative(page))  //如果page引用计数为0，返回0；否则计数加一，返回1
			goto next;

		/* Has the page moved or been split? */
		if (unlikely(page != xas_reload(&xas)))
			goto skip;
		page = find_subpage(page, xas.xa_index);

		if (!PageUptodate(page) ||
				PageReadahead(page) ||
				PageHWPoison(page))
			goto skip;
		if (!trylock_page(page))
			goto skip;

		if (page->mapping != mapping || !PageUptodate(page))
			goto unlock;

		max_idx = DIV_ROUND_UP(i_size_read(mapping->host), PAGE_SIZE);
		if (page->index >= max_idx)
			goto unlock;

		if (file->f_ra.mmap_miss > 0)
			file->f_ra.mmap_miss--;

		vmf->address += (xas.xa_index - last_pgoff) << PAGE_SHIFT;
		if (vmf->pte)
			vmf->pte += xas.xa_index - last_pgoff;
		last_pgoff = xas.xa_index;
		if (alloc_set_pte(vmf, NULL, page))
			goto unlock;

		
		if(page->mem_cgroup!=get_mem_cgroup_from_mm(current->mm)){
			//printk("%d: not same cgroup\n",current->pid);
            //首先对file中共享page计数加一
            //atomic_add(1,&(vmf->vma->find_page_count));
            atomic_add(1,&(file->find_page_count));

            //计数大于等于vma数量
            if(atomic_read(&(file->find_page_count))>=file->f_path.dentry->d_lockref.count || 
				atomic_read(&(file->find_page_count))<0){
                atomic_set(&(file->find_page_count),0); //count位置0 
                /*
                 * page所指mem_cgroup uncharge
                 * 当前进程的mem_cgroup charge
                 */
                // mem_cgroup_uncharge(page);
                // mem_cgroup_try_charge(page,current->mm,vmf->gfp_mask,&cgroup_temp,false);
                // mem_cgroup_commit_charge(page, cgroup_temp, false, false);
                //     //page->mem_cgroup=get_mem_cgroup_from_mm(current->mm);   //修改page所属mem_cgroup
				// 	page->mem_cgroup=cgroup_temp;

				// 	//message
				// 	atomic_add(1,&(vmf->vma->printk_count));
				// 	if(atomic_read(&(vmf->vma->printk_count))>=1000 || atomic_read(&(vmf->vma->printk_count))<0 )
				// 	{
				// 		atomic_set(&(vmf->vma->printk_count),0);
				// 		printk("there");
				// 	}

				printk("filemap_fault: pid %d  dentry_count %d \n",current->pid,file->f_path.dentry->d_lockref.count);

				//if(current->pid>2000)
				{
					mem_cgroup_uncharge(page);
                	mem_cgroup_try_charge(page,current->mm,vmf->gfp_mask,&cgroup_temp,false);
                	mem_cgroup_commit_charge(page, cgroup_temp, false, false);
				}

				// uncharge_page(page);
				// cgroup_temp=get_mem_cgroup_from_mm(current->mm);
				// try_charge(cgroup_temp, vmf->gfp_mask ,nr_pages);

				// commit_charge(page, cgroup_temp, false);

				// local_irq_disable();
				// mem_cgroup_charge_statistics(cgroup_temp, page, false, nr_pages);
				// memcg_check_events(cgroup_temp, page);
				// local_irq_enable();


				


                
            }
        }


		unlock_page(page);

		


		goto next;
unlock:
		unlock_page(page);
skip:
		put_page(page);
next:
		/* Huge page is mapped? No need to proceed. */
		if (pmd_trans_huge(*vmf->pmd))
			break;
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(filemap_map_pages);