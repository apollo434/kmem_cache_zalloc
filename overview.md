### kmem_cache_zalloc

** NOTE: Based on Linux v5.2.8**

First of all, review the key function call chain

```
kmem_cache_zalloc
  kmem_cache_alloc
    slab_allc(mm/slab.c)
      __do_cache_alloc
        ___cache_alloc
          ac = cpu_cache_get(cachep)
          or
          objp = cache_alloc_refill(cachep,flags)
          ac = cpu_cache_get(cachep)
```
Secondly, the key structure

1.struct kmem_cache (include/linux/slab_def.h)

```
/*
 * Definitions unique to the original Linux SLAB allocator.
 */

struct kmem_cache {
	struct array_cache __percpu *cpu_cache;//per_cpu数据，记录了本地高速缓存的信息，也是用于跟踪最近释放的对象，每次分配和释放都要直接访问它。

/* 1) Cache tunables. Protected by slab_mutex */
	unsigned int batchcount; //本地高速缓存转入和转出的大批数据数量
	unsigned int limit;//本地高速缓存中空闲对象的最大数目
	unsigned int shared;

	unsigned int size;
	struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

	slab_flags_t flags;		/* constant flags */
	unsigned int num;		/* # of objs per slab *//*slab中有多少个对象*/

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder;/*每个slab中有多少个页*/

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t allocflags; /*与伙伴系统交互时所提供的分配标识*/  

	size_t colour;			/* cache colouring range */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *freelist_cache; /* should be 3 list shrink to 1 list*/
	unsigned int freelist_size;

	/* constructor func */
	void (*ctor)(void *obj);/*构造函数*/

/* 4) cache creation/removal */
	const char *name;/*slab上的名字*/
	struct list_head list;//用于将高速缓存连入cache chain
	int refcount;
	int object_size;
	int align;

/* 5) statistics */ //一些用于调试用的变量
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. 'size' contains the total
	 * object size including these internal fields, while 'obj_offset'
	 * and 'object_size' contain the offset to the user object and its
	 * size.
	 */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */

#ifdef CONFIG_MEMCG
	struct memcg_cache_params memcg_params;
#endif
#ifdef CONFIG_KASAN
	struct kasan_cache kasan_info; /* for memory leak or use-after-free */
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif

	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */

	struct kmem_cache_node *node[MAX_NUMNODES];
};


```
2.struct array_cache (mm/slab.c)

```
/*
 * struct array_cache
 *
 * Purpose:
 * - LIFO ordering, to hand out cache-warm objects from _alloc
 * - reduce the number of linked list operations
 * - reduce spinlock operations
 *
 * The limit is stored in the per-cpu structure to reduce the data cache
 * footprint.
 *
 */
struct array_cache {
	unsigned int avail;/*当前cpu上有多少个可用的对象*/
	unsigned int limit;/*per_cpu里面最大的对象的个数，当超过这个值时，将对象返回给伙伴系统*/
	unsigned int batchcount;/*一次转入和转出的对象数量*/
	unsigned int touched;/*标示本地cpu最近是否被使用*/
	void *entry[];	/*
			 * Must have this definition in here for the proper
			 * alignment of array_cache. Also simplifies accessing
			 * the entries.
			 */
};

```

3.The relationship between these structure.
**** NOTE: Based on Linux v3.2 ****

![Alt text](/pic/relationship.png)

![Alt text](/pic/relationship1.png)

**** NOTE: Based on Linux v5.2.8 ****

```
kmem_cache                        
++++++++++++++++++++++++         ++++++++     ++++++++
+ array_cache __percpu + =======>  cpu 0  .... cpu n     per cpu arrage
++++++++++++++++++++++++         ++++++++     ++++++++
+                      +
++++++++++++++++++++++++          ++++++++++++++      ++++++++++++++
+ freelist_cache       + <=======>+ kmem_cache + <==> + kmem_cache + for free list
++++++++++++++++++++++++          ++++++++++++++      ++++++++++++++
+                      +
++++++++++++++++++++++++
+ kmem_cache_node      + ========> NUMA *node[MAX_NUMNODES]
++++++++++++++++++++++++
```

4.Detailed comments for kmem_cache_zalloc

```

```

### Purpose

For ** kmalloc ** or directly call it, like ** dst_entry **

1. I.E. dst_entry

** NOTE **
通过在一张路由表(struct fib_table)中，根据查询路由的目的IP地址(key)在其路由哈希表(struct fn_hash)中找到一个路由域(struct fn_zone)，并在路由域中匹配到一个key相等的路由节点(struct fib_node)，取其路由别名(struct fib_alias)和路由信息(struct fib_info)，生成一个路由查询结果(struct fib_result)。
    路由查询结果还不能直接供发送IP数据报使用，接下来，还必须根据这个查询结果生成一个路由目的入口(dst_entry)，根据目的入口才可以发送IP 数据报，目的入口用结构体struct dst_entry表示，在实际使用时，还在它的外面包装了一层，形成一个结构体struct rtable

路由缓存就是在ip_route_input、ip_route_output中会被创建。

```


```

2.Brush up the networking stack.

```

```
