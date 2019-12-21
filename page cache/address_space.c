/**
 * struct xarray - The anchor of the XArray.
 * @xa_lock: Lock that protects the contents of the XArray.
 *
 * To use the xarray, define it statically or embed it in your data structure.
 * It is a very small data structure, so it does not usually make sense to
 * allocate it separately and keep a pointer to it in your data structure.
 *
 * You may use the xa_lock to protect your own data structures as well.
 */
/*
 * If all of the entries in the array are NULL, @xa_head is a NULL pointer.
 * If the only non-NULL entry in the array is at index 0, @xa_head is that
 * entry.  If any other entry in the array is non-NULL, @xa_head points
 * to an @xa_node.
 */
struct xarray {
	spinlock_t	xa_lock;
/* private: The rest of the data structure is not to be used directly. */
	gfp_t		xa_flags;
	void __rcu *	xa_head;
};

/*
 * Leftmost-cached rbtrees.
 *
 * We do not cache the rightmost node based on footprint
 * size vs number of potential users that could benefit
 * from O(1) rb_last(). Just not worth it, users that want
 * this feature can always implement the logic explicitly.
 * Furthermore, users that want to cache both pointers may
 * find it a bit asymmetric, but that's ok.
 */
struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

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
	struct xarray		i_pages;       //该文件载入page cache的页
	gfp_t			gfp_mask;
	atomic_t		i_mmap_writable;	//i_mmap中vma计数
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
 * pace cache隔离需要修改的应该是缺页中断时，文件映射类型的第二个进程读入的页计数
 * Q1:不同进程打开同一文件inode是否一致（open)？ 一致
 * Q2:mmap同一文件address_space是否一致(mmap)？ 貌似一致
 * Q3:共享同一文件的vma是否在都在address-space的最优树？ 都在
 * 
 * page cache包括 文件映射页（包括file cache与temfs映射cache）
 * 
 * 初步解决方案：
 * 在address_space中增加count位，在缺页中断时如果page已经在page cache中进行0、1转换，
 * 当count为1时将该page对应的vma的进程uncharge，该进程charge
 * 实现在缺页中断处
 * 
 * Q1：怎么找到最初charge该page的进程？
 * A1：page中含有指向mem_cgroup的成员，所以修改计数时也需要修改该成员。
 * 
 * Q2：对于每一个进程都需要一个count位，并且count循环数需要是共享进程数，共享数怎么得？count位怎么设计？
 * A2：open或mmap时应该会有引用位的增加，inode或address_space(看mmap源码)，
 *      count可以考虑加到vma中
 * 		address_space中的i_mmap_writable为vma的引用计数 (mmap源码)
 * 
 * Q3：对cgroup memory接口文件的修改怎么实现？
 * 
 * 
 * 
 * 注：address_space不是在mmap期间分配
 * 
 * 
 * ps：缺页中断时，如果在page cahche找到page，需要判断引入该page的进程是否为该进程本身
 * 		如果是该进程本身无需处理，不是才需要调整计数
 * 
*/
