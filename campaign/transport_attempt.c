/* Count the original TCP four-tuple before the deadline classifier.
 * This passive classifier always continues to the original verdict. */
#include <linux/bpf.h>
struct sample {
    __u64 frames, payload_frames, payload_bytes, first, last, first_data, last_data;
    __u64 first_seq, last_seq, fin, rst;
};
struct {
    int (*type)[BPF_MAP_TYPE_ARRAY]; int (*max_entries)[2];
    __u32 *key; struct sample *value;
} history __attribute__((section(".maps"),used));
static long (*load)(void *,__u32,void *,__u32)=(void *)BPF_FUNC_skb_load_bytes;
static void *(*lookup)(void *, const void *)=(void *)BPF_FUNC_map_lookup_elem;
static __u64 (*clock_ns)(void)=(void *)BPF_FUNC_ktime_get_boot_ns;
static inline __u16 word(const unsigned char *p){ return ((__u16)p[0]<<8)|p[1]; }
static inline __u32 wide(const unsigned char *p){ return ((__u32)word(p)<<16)|word(p+2); }

__attribute__((section("classifier"),used))
int observe(struct __sk_buff *skb) {
    unsigned char eth[14], ip[20], tcp[20];
    if (load(skb,0,eth,sizeof(eth)) || word(eth+12)!=0x0800 ||
        load(skb,14,ip,sizeof(ip)) || ip[0]>>4!=4 || ip[9]!=6 ||
        wide(ip+12)!=SRC_IP || wide(ip+16)!=DST_IP) return -1;
    __u32 ihl=(ip[0]&15)*4;
    if (ihl<20 || load(skb,14+ihl,tcp,sizeof(tcp)) ||
        word(tcp)!=SRC_PORT || word(tcp+2)!=DST_PORT) return -1;
    __u32 thl=(tcp[12]>>4)*4, size=word(ip+2);
    if (thl<20 || size<ihl+thl) return -1;
    __u64 t=clock_ns();
    __u32 key=t>=DEADLINE_NS;
    struct sample *s=lookup(&history,&key);
    if (!s) return -1;
    if (!s->frames) s->first=t;
    s->frames++; s->last=t;
    if (tcp[13]&1) s->fin++;
    if (tcp[13]&4) s->rst++;
    if (size>ihl+thl) {
        if (!s->payload_frames) { s->first_data=t; s->first_seq=wide(tcp+4); }
        s->payload_frames++; s->payload_bytes+=size-ihl-thl;
        s->last_data=t; s->last_seq=wide(tcp+4);
    }
    return -1;
}
char license_text[] __attribute__((section("license"),used))="GPL";
