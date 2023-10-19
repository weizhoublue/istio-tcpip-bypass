// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 Intel Corporation */

// 各种数据结构，能避免编译机器需要安装 header
#include "vmlinux.h"
// 各种 bpf api ， 最常用
#include <bpf/bpf_helpers.h>
// for bpf_ntohl
#include <bpf/bpf_endian.h>
#include "bpf_sockops.h"


/*  BPF_PROG_TYPE_SK_MSG
在用户态程序调用以下系统调用时，会触发 该类型的 eBPF 程序：
	sendmsg 和 recvmsg
	sendfile
*/
// struct sk_msg_md  https://elixir.bootlin.com/linux/v6.5.7/source/include/uapi/linux/bpf.h#L6259
SEC("sk_msg")
int bpf_redir_proxy(struct sk_msg_md *msg)
{
    uint32_t rc;
    uint32_t* debug_val_ptr;
    uint32_t debug_val;
    uint32_t debug_on_index = 0;
    uint32_t debug_pckts_index = 1;
    struct socket_4_tuple proxy_key = {};
    /* for inbound traffic */
    struct socket_4_tuple key = {};
    /* for outbound and envoy<->envoy traffic*/
    struct socket_4_tuple *key_redir = NULL;

    // proxy_key 取出正向4元祖
    // key 取出反向4元祖
    sk_msg_extract4_keys(msg, &proxy_key, &key);
    if (key.local.ip4 == INBOUND_ENVOY_IP || key.remote.ip4 == INBOUND_ENVOY_IP) {
        rc = bpf_msg_redirect_hash(msg, &map_redir, &key, BPF_F_INGRESS);
    } else {
        // 查询曾经是否有过该记录
        // 该记录在 bpf_sockops.c 记录
        key_redir = bpf_map_lookup_elem(&map_proxy, &proxy_key);
        if (key_redir == NULL) {
            return SK_PASS;
        }
        // 发生重定向 redirect it to the socket referenced by *map*
        /*
        BPF_MAP_TYPE_SOCKMAP`` and ``BPF_MAP_TYPE_SOCKHASH`` maps can be used to
        redirect skbs between sockets or to apply policy at the socket level based on
        the result of a BPF (verdict) program with the help of the BPF helpers
        */
        rc = bpf_msg_redirect_hash(msg, &map_redir, key_redir, BPF_F_INGRESS);
    }

    if (rc == SK_PASS) {
        // debug_map map 的  debug_on_index 索引，记录是否 使能 调试 ； debug_pckts_index 索引 记录 pass 的数据包数量
        // 如果开启 debug， 则打印日志
        debug_val_ptr = bpf_map_lookup_elem(&debug_map, &debug_on_index);
        if (debug_val_ptr && *debug_val_ptr == 1) {
            char info_fmt[] = "data redirection succeed: [%x]->[%x]\n";
            bpf_trace_printk(info_fmt, sizeof(info_fmt), proxy_key.local.ip4, proxy_key.remote.ip4);

            debug_val_ptr = bpf_map_lookup_elem(&debug_map, &debug_pckts_index);
            if (debug_val_ptr == NULL) {
                debug_val = 0;
                debug_val_ptr = &debug_val;
            }
            // 值加 1 ， 避免数量包并发 导致该 ebpf 程序并发，此处做了原子操作
            __sync_fetch_and_add(debug_val_ptr, 1);
            // 写回 数据到 map
            // bpf_map_update_elem  是一个原子操作，通常是线程安全的
            bpf_map_update_elem(&debug_map, &debug_pckts_index, debug_val_ptr, BPF_ANY);

        }
    }
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
