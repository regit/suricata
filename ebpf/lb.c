/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stddef.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/filter.h>

#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

static __always_inline int ipv4_hash(struct __sk_buff *skb)
{
    return  skb->local_ip4 + skb->remote_ip4;
}

static __always_inline int ipv6_hash(struct __sk_buff *skb)
{
    __u32 hash;

    hash = skb->local_ip6[0] + skb->remote_ip6[0];
    hash += skb->local_ip6[1] + skb->remote_ip6[1];
    hash += skb->local_ip6[2] + skb->remote_ip6[2];
    hash += skb->local_ip6[3] + skb->remote_ip6[3];

    return hash;
}

int  __section("loadbalancer") lb(struct __sk_buff *skb) {
    __u32 nhoff = BPF_LL_OFF + ETH_HLEN;

    skb->cb[0] = nhoff;

    switch (skb->protocol) {
        case __constant_htons(ETH_P_IP):
            return ipv4_hash(skb);
        case __constant_htons(ETH_P_IPV6):
            return ipv6_hash(skb);
        default:
#if 0
            {
                char fmt[] = "Got proto %u\n";
                bpf_trace_printk(fmt, sizeof(fmt), h_proto);
                break;
            }
#else
            break;
#endif
    }
    /* hash on proto by default */
    return skb->protocol;
}

char __license[] __section("license") = "GPL";

/* libbpf needs version section to check sync of eBPF code and kernel
 * but socket filter don't need it */
__u32 __version __section("version") = LINUX_VERSION_CODE;
