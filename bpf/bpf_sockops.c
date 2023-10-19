// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 Intel Corporation */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"

static inline void bpf_sock_ops_active_establish_cb(struct bpf_sock_ops *skops) {
    struct socket_4_tuple key = {};

    sk_ops_extract4_key(skops, &key);

    char tuple_info_src[] = "active data tuple : [%x]:%x ";
    bpf_trace_printk(tuple_info_src, sizeof(tuple_info_src), key.local.ip4, key.local.port  );
    char tuple_info_dst[] = "-> [%x]:%x\n";
    bpf_trace_printk(tuple_info_dst, sizeof(tuple_info_dst), key.remote.ip4, key.remote.port  );

    if (key.local.ip4 == INBOUND_ENVOY_IP) {
        // update the SOCKHASH map ，供后续重定向
        // 以 4 元组为 key， 以 skops 为value
        bpf_sock_hash_update(skops, &map_redir, &key, BPF_ANY);
        return;
    }
    if (key.local.ip4 == key.remote.ip4) {
        return;
    }

    /* update map_active_estab*/
    // key 记录 源地址，value 记录 目的地址
    bpf_map_update_elem(&map_active_estab, &key.local, &key.remote, BPF_NOEXIST);

    /* update map_redir */
    // update the SOCKHASH map ，，供后续重定向
    bpf_sock_hash_update(skops, &map_redir, &key, BPF_ANY);
}

static inline void bpf_sock_ops_passive_establish_cb(struct bpf_sock_ops *skops) {
    struct socket_4_tuple key = {};
    struct socket_4_tuple proxy_key = {};
    struct socket_4_tuple proxy_val = {};
    struct addr_2_tuple *original_dst;

    sk_ops_extract4_key(skops, &key);

    char tuple_info_src[] = "passive data tuple : [%x]:%x ";
    bpf_trace_printk(tuple_info_src, sizeof(tuple_info_src), key.local.ip4, key.local.port  );
    char tuple_info_dst[] = "-> [%x]:%x\n";
    bpf_trace_printk(tuple_info_dst, sizeof(tuple_info_dst), key.remote.ip4, key.remote.port  );

    if (key.remote.ip4 == INBOUND_ENVOY_IP) {
        bpf_sock_hash_update(skops, &map_redir, &key, BPF_ANY);
    }
    original_dst = bpf_map_lookup_elem(&map_active_estab, &key.remote);
    if (original_dst == NULL) {
        return;
    }
    /* update map_proxy */
    proxy_key.local = key.remote;
    proxy_key.remote = *original_dst;
    proxy_val.local = key.local;
    proxy_val.remote = key.remote;
    bpf_map_update_elem(&map_proxy, &proxy_key, &proxy_val, BPF_ANY);
    bpf_map_update_elem(&map_proxy, &proxy_val, &proxy_key, BPF_ANY);

    /* update map_redir */
    // key 记录
    bpf_sock_hash_update(skops, &map_redir, &key, BPF_ANY);

    /* delete element in map_active_estab*/
    // 使用完毕 就可以删除了
    bpf_map_delete_elem(&map_active_estab, &key.remote);
}

static inline void bpf_sock_ops_state_cb(struct bpf_sock_ops *skops) {
    struct socket_4_tuple key = {};
    sk_ops_extract4_key(skops, &key);
    /* delete elem in map_proxy */
    bpf_map_delete_elem(&map_proxy, &key);
    /* delete elem in map_active_estab */
    bpf_map_delete_elem(&map_active_estab, &key.local);
}

/* BPF_PROG_TYPE_SOCK_OPS
    主要完成记录 SOCKHASH ， 供 redir.c 进行重定向
*/
// struct bpf_sock_ops https://elixir.bootlin.com/linux/v6.5.7/source/include/uapi/linux/bpf.h#L6474
SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    if (!(skops->family == AF_INET || skops->remote_ip4)) {
         // 不支持 ipv6 ，或者 ipv4 时没有 remote_ip4 时 则 返回
        /* support dual-stack socket */
        return 0;
    }

    /*  set skops->bpf_sock_ops_cb_flags
             		* **BPF_SOCK_OPS_RTO_CB_FLAG** (retransmission time out)
              		* **BPF_SOCK_OPS_RETRANS_CB_FLAG** (retransmission)
              		* **BPF_SOCK_OPS_STATE_CB_FLAG** (TCP state change)
              		* **BPF_SOCK_OPS_RTT_CB_FLAG** (every RTT)
    */
    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
    switch (skops->op) {
    // 收到了 synack，主动建联 tcp 完成3握手
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_sock_ops_active_establish_cb(skops);
        break;
    // 收到了 ack ， 被动建联 tcp 完成3握手
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        bpf_sock_ops_passive_establish_cb(skops);
        break;
    // Called when TCP changes state
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE) {
            // 删除map 中的数据
            bpf_sock_ops_state_cb(skops);
        }
        break;
    default:
        break;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
