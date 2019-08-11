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

1. struct kmem_cache (include/linux/slab_def.h)

```
/*
 * Definitions unique to the original Linux SLAB allocator.
 */

struct kmem_cache {
	struct array_cache __percpu *cpu_cache;

/* 1) Cache tunables. Protected by slab_mutex */
	unsigned int batchcount;
	unsigned int limit;
	unsigned int shared;

	unsigned int size;
	struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

	slab_flags_t flags;		/* constant flags */
	unsigned int num;		/* # of objs per slab */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t allocflags;

	size_t colour;			/* cache colouring range */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *freelist_cache;
	unsigned int freelist_size;

	/* constructor func */
	void (*ctor)(void *obj);

/* 4) cache creation/removal */
	const char *name;
	struct list_head list;
	int refcount;
	int object_size;
	int align;

/* 5) statistics */
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
	struct kasan_cache kasan_info;
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif

	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */

	struct kmem_cache_node *node[MAX_NUMNODES];
};


```
2. struct array_cache (mm/slab.c)

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
	unsigned int avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int touched;
	void *entry[];	/*
			 * Must have this definition in here for the proper
			 * alignment of array_cache. Also simplifies accessing
			 * the entries.
			 */
};

```

3. The relationship between these structure.
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
