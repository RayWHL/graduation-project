static const struct vm_operations_struct ext4_file_vm_ops = {
	.fault		= ext4_filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite   = ext4_page_mkwrite,
};


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


/*
 * vm_fault is filled by the the pagefault handler and passed to the vma's
 * ->fault function. The vma's ->fault is responsible for returning a bitmask
 * of VM_FAULT_xxx flags that give details about how the fault was handled.
 *
 * MM layer fills up gfp_mask for page allocations but fault handler might
 * alter it if its implementation requires a different allocation context.
 *
 * pgoff should be used in favour of virtual_address, if possible.
 */
struct vm_fault {
	struct vm_area_struct *vma;	/* Target VMA */
	unsigned int flags;		/* FAULT_FLAG_xxx flags */
	gfp_t gfp_mask;			/* gfp mask to be used for allocations */
	pgoff_t pgoff;			/* Logical page offset based on vma */
	unsigned long address;		/* Faulting virtual address */
	pmd_t *pmd;			/* Pointer to pmd entry matching
					 * the 'address' */
	pud_t *pud;			/* Pointer to pud entry matching
					 * the 'address'
					 */
	pte_t orig_pte;			/* Value of PTE at the time of fault */

	struct page *cow_page;		/* Page handler may use for COW fault */
	struct mem_cgroup *memcg;	/* Cgroup cow_page belongs to */
	struct page *page;		/* ->fault handlers should return a
					 * page here, unless VM_FAULT_NOPAGE
					 * is set (which is also implied by
					 * VM_FAULT_ERROR).
					 */
	/* These three entries are valid only while holding ptl lock */
	pte_t *pte;			/* Pointer to pte entry matching
					 * the 'address'. NULL if the page
					 * table hasn't been allocated.
					 */
	spinlock_t *ptl;		/* Page table lock.
					 * Protects pte page table if 'pte'
					 * is not NULL, otherwise pmd.
					 */
	pgtable_t prealloc_pte;		/* Pre-allocated pte page table.
					 * vm_ops->map_pages() calls
					 * alloc_set_pte() from atomic context.
					 * do_fault_around() pre-allocates
					 * page table to avoid allocation from
					 * atomic context.
					 */
};

/*
 * Walk a vmap address to the struct page it maps.
 */
struct page *vmalloc_to_page(const void *vmalloc_addr)
{
	unsigned long addr = (unsigned long) vmalloc_addr;
	struct page *page = NULL;
	pgd_t *pgd = pgd_offset_k(addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;

	/*
	 * XXX we might need to change this if we add VIRTUAL_BUG_ON for
	 * architectures that do not vmalloc module space
	 */
	VIRTUAL_BUG_ON(!is_vmalloc_or_module_addr(vmalloc_addr));

	if (pgd_none(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;
	pud = pud_offset(p4d, addr);

	/*
	 * Don't dereference bad PUD or PMD (below) entries. This will also
	 * identify huge mappings, which we may encounter on architectures
	 * that define CONFIG_HAVE_ARCH_HUGE_VMAP=y. Such regions will be
	 * identified as vmalloc addresses by is_vmalloc_addr(), but are
	 * not [unambiguously] associated with a struct page, so there is
	 * no correct value to return for them.
	 */
	WARN_ON_ONCE(pud_bad(*pud));
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	pmd = pmd_offset(pud, addr);
	WARN_ON_ONCE(pmd_bad(*pmd));
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;

	ptep = pte_offset_map(pmd, addr);
	pte = *ptep;
	if (pte_present(pte))
		page = pte_page(pte);
	pte_unmap(ptep);
	return page;
}

/*
 * vm_area_struct函数指针fault指向的函数   wrong
 * Local (non-chip) user memory is not mapped right away but as it is
 * accessed by the user-level code.
 */
static vm_fault_t vma_fault(struct vm_fault *vmf)
{
	struct page *page;

	page = vmalloc_to_page((void *)(vmf->pgoff << PAGE_SHIFT));
	if (!page)
		return VM_FAULT_SIGBUS;

	get_page(page);
	vmf->page = page;

	return 0;
}

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
 * The mmap_sem must have been held on entry, and may have been
 * released depending on flags and vma->vm_ops->fault() return value.
 * See filemap_fault() and __lock_page_retry().
 * 文件页读到page cache
 */
static vm_fault_t __do_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret;

	/*
	 * Preallocate pte before we take page_lock because this might lead to
	 * deadlocks for memcg reclaim which waits for pages under writeback:
	 *				lock_page(A)
	 *				SetPageWriteback(A)
	 *				unlock_page(A)
	 * lock_page(B)
	 *				lock_page(B)
	 * pte_alloc_pne
	 *   shrink_page_list
	 *     wait_on_page_writeback(A)
	 *				SetPageWriteback(B)
	 *				unlock_page(B)
	 *				# flush A, B to clear the writeback
	 */
	if (pmd_none(*vmf->pmd) && !vmf->prealloc_pte) {        //不存在对应页表项
		vmf->prealloc_pte = pte_alloc_one(vmf->vma->vm_mm);
		if (!vmf->prealloc_pte)
			return VM_FAULT_OOM;
		smp_wmb(); /* See comment in __pte_alloc() */
	}

    ret = vma->vm_ops->fault(vmf);		//调用fault方法，会调用readpage方法，包含charge操作
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY |
			    VM_FAULT_DONE_COW)))
		return ret;

	if (unlikely(PageHWPoison(vmf->page))) {
		if (ret & VM_FAULT_LOCKED)
			unlock_page(vmf->page);
		put_page(vmf->page);
		vmf->page = NULL;
		return VM_FAULT_HWPOISON;
	}

	if (unlikely(!(ret & VM_FAULT_LOCKED)))
		lock_page(vmf->page);
	else
		VM_BUG_ON_PAGE(!PageLocked(vmf->page), vmf->page);

	return ret;
}

/**
 * finish_fault - finish page fault once we have prepared the page to fault
 *
 * @vmf: structure describing the fault
 *
 * This function handles all that is needed to finish a page fault once the
 * page to fault in is prepared. It handles locking of PTEs, inserts PTE for
 * given page, adds reverse page mapping, handles memcg charges and LRU
 * addition.
 *
 * The function expects the page to be locked and on success it consumes a
 * reference of a page being mapped (for the PTE which maps it).
 *
 * Return: %0 on success, %VM_FAULT_ code in case of error.
 */
vm_fault_t finish_fault(struct vm_fault *vmf)
{
	struct page *page;
	vm_fault_t ret = 0;

	/* Did we COW the page? */
	if ((vmf->flags & FAULT_FLAG_WRITE) &&
	    !(vmf->vma->vm_flags & VM_SHARED))
		page = vmf->cow_page;
	else
		page = vmf->page;

	/*
	 * check even for read faults because we might have lost our CoWed
	 * page
	 */
	if (!(vmf->vma->vm_flags & VM_SHARED))
		ret = check_stable_address_space(vmf->vma->vm_mm);
	if (!ret)
		ret = alloc_set_pte(vmf, vmf->memcg, page);
	if (vmf->pte)
		pte_unmap_unlock(vmf->pte, vmf->ptl);
	return ret;
}


