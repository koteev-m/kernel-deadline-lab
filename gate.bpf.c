// SPDX-License-Identifier: GPL-2.0
// Build one classifier per deadline. No maps, packet writes or update operation.
#ifndef DEADLINE_NS
#define DEADLINE_NS 0ULL
#endif
enum { act_ok = 0, act_drop = 2, boot_ns_helper = 125 };
#ifdef CHECK_LINUX_UAPI
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
_Static_assert(BPF_FUNC_ktime_get_boot_ns == boot_ns_helper, "helper ABI");
_Static_assert(TC_ACT_OK == act_ok && TC_ACT_SHOT == act_drop, "tc actions");
#endif

static unsigned long long (*const boot_ns)(void) = (void *)boot_ns_helper;

__attribute__((section("classifier"), used))
int deadline_gate(void *skb)
{
    (void)skb;
    if (DEADLINE_NS == 0ULL)
        return act_drop;
    return boot_ns() < DEADLINE_NS ? act_ok : act_drop;
}

__attribute__((section("license"), used))
char program_license[] = "GPL";
