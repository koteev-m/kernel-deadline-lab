/* Read-only observation of the two dedicated socket tuples on the offline veth.
 * Each hook gets a separate map. Returning UNSPEC leaves all verdicts downstream.
 */
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <stddef.h>

_Static_assert(offsetof(struct tcp_info, tcpi_unacked) == 24, "unacked ABI");
_Static_assert(offsetof(struct tcp_info, tcpi_total_retrans) == 100, "retrans ABI");
_Static_assert(offsetof(struct tcp_info, tcpi_bytes_acked) == 120, "bytes acked ABI");

struct sample {
    __u64 clock;
    __u32 seq, ack;
    __u16 sport, dport, length;
    __u8 version, flags;
    __u32 src, dst;
};
_Static_assert(sizeof(struct sample) == 32, "record layout");

struct {
    int (*type)[BPF_MAP_TYPE_ARRAY];
    int (*max_entries)[257];
    __u32 *key;
    struct sample *value;
} series __attribute__((section(".maps"), used));

static void *(*lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*load_bytes)(void *, __u32, void *, __u32) = (void *)BPF_FUNC_skb_load_bytes;
static __u64 (*boot_ns)(void) = (void *)BPF_FUNC_ktime_get_boot_ns;

static inline __u16 word(const unsigned char *p) { return (p[0] << 8) | p[1]; }
static inline __u32 wide(const unsigned char *p) { return ((__u32)word(p) << 16) | word(p+2); }

__attribute__((section("classifier"), used))
int observe(struct __sk_buff *skb)
{
    unsigned char eth[14], ip[40], tcp[20];
    struct sample event = {};
    int offset, transport;
    if (load_bytes(skb, 0, eth, sizeof(eth))) return -1;
    if (word(eth+12) == 0x0800) {
        if (load_bytes(skb, 14, ip, 20) || ip[0] != 0x45 || ip[9] != 6) return -1;
        if ((wide(ip+12)>>8) != 0xc00002 || (wide(ip+16)>>8) != 0xc00002) return -1;
        event.version = 4; event.src=ip[15]; event.dst=ip[19];
        offset = 34; transport = word(ip+2)-20;
    } else if (word(eth+12) == 0x86dd) {
        if (load_bytes(skb, 14, ip, 40) || ip[6] != 6) return -1;
        if (wide(ip+8)!=0x20010db8 || wide(ip+12)!=0x00680000 || wide(ip+16) ||
            wide(ip+24)!=0x20010db8 || wide(ip+28)!=0x00680000 || wide(ip+32)) return -1;
        event.version=6; event.src=wide(ip+20); event.dst=wide(ip+36);
        offset=54; transport=word(ip+4);
    } else return -1;
    if (!((event.src==1 && event.dst==2) || (event.src==2 && event.dst==1))) return -1;
    if (load_bytes(skb, offset, tcp, sizeof(tcp))) return -1;
    event.sport=word(tcp); event.dport=word(tcp+2);
    if (!((event.sport==24680 && event.dport==24681) ||
          (event.sport==24681 && event.dport==24680))) return -1;
    event.seq=wide(tcp+4); event.ack=wide(tcp+8); event.flags=tcp[13];
    int header=(tcp[12]>>4)*4;
    if (header<20 || transport<header) return -1;
    event.length=transport-header;
    event.clock=boot_ns();
    __u32 zero=0;
    struct sample *head=lookup(&series,&zero);
    if (head) {
        __u64 n=__sync_fetch_and_add(&head->clock,1);
        if (n<256) {
            __u32 key=n+1;
            struct sample *row=lookup(&series,&key);
            if (row) *row=event;
        }
    }
    return -1;
}
char license_text[] __attribute__((section("license"), used))="GPL";
