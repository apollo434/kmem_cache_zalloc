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

2.1 Receive packets

** NOTE: **
**NF_HOOK** Macro is made for Networking Firewall

```
ip_rcv
  ip_rcv_finish
    dst_input

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

/*
 * IP receive entry point
 */
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,struct net_device *orig_dev)
{
  ....

  return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
  		       net, NULL, skb, dev, NULL,
  		       ip_rcv_finish);
}

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
  ....
  /* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_rcv(skb);
  ....
  ret = ip_rcv_finish_core(net, sk, skb, dev);
  ....
  dst_input(skb);
  ....
}

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
	return skb_dst(skb)->input(skb);
}

The skb_dst(skb)->input(skb) has been defined in l3mdev_ip_rcv(skb) and ip_rcv_finish_core(net, sk, skb, dev);

```

2.2 Send Package from local

** NOTE: **

Who can call dst_output?

1)The Router has been selected via Router Subsystem, means skb->dst is ready.

2) The IP Head has been done, will send it out
```
dst_output
  ip_mc_output or
  ip_fragment  or
  ip_output
    ip_finish_output
      ip_finish_output_2
        Neighborhood System()
          dev_queue_xmit


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

/* Output packet to network from transport.  */
static inline int dst_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
  return skb_dst(skb)->output(net, sk, skb);
}

The skb_dst(skb)->onput(skb) has been defined in Router Subsystem.

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
			    net, sk, skb, NULL, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

static int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
  ....
#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
	if (skb_dst(skb)->xfrm) {
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(net, sk, skb);
	}
#endif
  ....

	if (skb->len > mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU))
		return ip_fragment(net, sk, skb, mtu, ip_finish_output2);

	return ip_finish_output2(net, sk, skb);
}

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

static int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
  ....
  /*  */
  if (lwtunnel_xmit_redirect(dst->lwtstate)) {
		int res = lwtunnel_xmit(skb);

		if (res < 0 || res == LWTUNNEL_XMIT_DONE)
			return res;
	}
  ....   
  /* How to go to the Neighborhood Subsystem */
  rcu_read_lock_bh();
	neigh = ip_neigh_for_gw(rt, skb, &is_v6gw);
	if (!IS_ERR(neigh)) {
		int res;

		sock_confirm_neigh(skb, neigh);
		/* if crossing protocols, can not use the cached header */
		res = neigh_output(neigh, skb, is_v6gw);
		rcu_read_unlock_bh();
		return res;
	}
	rcu_read_unlock_bh();

```
2.3 Forwarding

```
ip_forward
  xfrm4_route_forward
  ip_forward_finish
    dst_ouput

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
int ip_forward(struct sk_buff *skb)
{
  ....
	if (!xfrm4_route_forward(skb))
		goto drop;
  ....
	return NF_HOOK(NFPROTO_IPV4, NF_INET_FORWARD,
		       net, NULL, skb, skb->dev, rt->dst.dev,
		       ip_forward_finish);
  ....
}

static int ip_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
  ....
	return dst_output(net, sk, skb);
}
```
