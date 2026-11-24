/* Attached only to a private AF_PACKET/SOCK_RAW socket in a guest namespace.
 * Return 0 discards the copy for this socket. There is no traffic-control hook. */
#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
struct {
    int (*type)[BPF_MAP_TYPE_RINGBUF];
    int (*max_entries)[1 << 23];
} records SEC(".maps");

struct totals { __u64 seen, lost, unreadable; };
struct {
    int (*type)[BPF_MAP_TYPE_ARRAY];
    int (*max_entries)[1];
    __u32 *key;
    struct totals *value;
} counts SEC(".maps");

static void *(*lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static void *(*reserve)(void *, __u64, __u64) = (void *)BPF_FUNC_ringbuf_reserve;
static void (*submit)(void *, __u64) = (void *)BPF_FUNC_ringbuf_submit;
static void (*discard)(void *, __u64) = (void *)BPF_FUNC_ringbuf_discard;
static long (*copy)(void *, __u32, void *, __u32) = (void *)BPF_FUNC_skb_load_bytes;
static __u64 (*clock_ns)(void) = (void *)BPF_FUNC_ktime_get_boot_ns;

struct entry { __u64 ordinal, boot; __u32 index, size, direction, reserved; };
#define RECORD(cap) do { \
    struct entry *e = reserve(&records, sizeof(*e) + cap, 0); \
    if (!e) { __sync_fetch_and_add(&s->lost, 1); return 0; } \
    e->ordinal = n; e->boot = when; e->index = skb->ifindex; e->size = size; \
    e->direction = skb->pkt_type; e->reserved = 0; \
    if (copy(skb, 0, e+1, 1+((size-1) & (cap-1)))) { \
        __sync_fetch_and_add(&s->unreadable, 1); discard(e, 0); \
    } else { submit(e, 0); } \
    return 0; \
} while (0)

SEC("socket")
int receive_copy(struct __sk_buff *skb)
{
    __u64 when = clock_ns();
    __u32 zero = 0, size = skb->len;
    struct totals *s = lookup(&counts, &zero);
    if (!s) return 0;
    __u64 n = __sync_fetch_and_add(&s->seen, 1);
    if (size >= 14 && size <= 2048) RECORD(2048);
    if (size > 2048 && size <= 65536) RECORD(65536);
    __sync_fetch_and_add(&s->unreadable, 1);
    return 0;
}

char receiver_license[] SEC("license") = "GPL";
