// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 Intel Corporation */
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef NULL
#define NULL ((void*)0)
#endif

#define INBOUND_ENVOY_IP 0x600007f
#define SOCKOPS_MAP_SIZE 65535

#include <bpf/bpf_endian.h>

struct addr_2_tuple {
    uint32_t ip4;
    uint32_t port;
};

struct socket_4_tuple {
    struct addr_2_tuple local;
    struct addr_2_tuple remote;
};

/* when active establish, record local addr as key and remote addr as value
|--------------------------------------------------------------------|
|   key(local ip, local port)   |     Val(remote ip, remoteport)     |
|--------------------------------------------------------------------|
|        A-ip,A-app-port        |    B-cluster-ip,B-cluster-port     |
|--------------------------------------------------------------------|
|       A-ip,A-envoy-port       |              B-ip,B-port           |
|--------------------------------------------------------------------|
*/
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        // BPF_MAP_TYPE_HASH 的 key 和 values 可以是任意的数据类型
        __uint(max_entries, SOCKOPS_MAP_SIZE);
        __type(key, struct addr_2_tuple);
        __type(value, struct addr_2_tuple);
        /*
        enum libbpf_pin_type {
        	LIBBPF_PIN_NONE,
        	PIN_BY_NAME: pin maps by name (in /sys/fs/bpf by default)
        	LIBBPF_PIN_BY_NAME,
        };
        */
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_active_estab SEC(".maps");

/* This is a proxy map to store current socket 4-tuple and other side socket 4-tuple
|-------------------------------------------------------------------------------------------|
|          key(current socket 4-tuple)        |        Val(other side socket 4-tuple)       |
|-------------------------------------------------------------------------------------------|
| A-ip,A-app-port,B-cluster-ip,B-cluster-port |    127.0.0.1,A-outbound,A-ip:A-app-port     |
|-------------------------------------------------------------------------------------------|
|   127.0.0.1,A-outbound,A-ip:A-app-port      | A-ip:A-app-port,B-cluster-ip,B-cluster-port |
|-------------------------------------------------------------------------------------------|
*/

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, SOCKOPS_MAP_SIZE);
        __type(key, struct socket_4_tuple);
        __type(value, struct socket_4_tuple);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_proxy SEC(".maps");

/* This a sockhash map for sk_msg redirect
|------------------------------------------------------------------------|
|  key(local_ip:local_port, remote_ip:remote_port) |     Val(skops)      |
|------------------------------------------------------------------------|
|   A-ip:A-app-port, B-cluster-ip,B-cluster-port   |     A-app-skops     |    <--- A-app active_estab CB
|------------------------------------------------------------------------|
|          A-ip:A-envoy-port, B-ip:B-port          |    A-envoy-skops    |    <--- A-envoy active_estab CB
|------------------------------------------------------------------------|
|       127.0.0.1:A-outbound, A-ip:A-app-port      |   A-outbound-skops  |    <--- A-outbound passive_estab CB
|------------------------------------------------------------------------|
|        B-ip:B-inbound, A-ip:A-envoy-port         |   B-inbound-skops   |    <--- B-inbound passive_estab CB
|------------------------------------------------------------------------|
*/
/*
 使用 bpf_sock_hash_update 来更新
 配合 bpf_sk_redirect_hash 来重定向数据包
*/
struct {
        __uint(type, BPF_MAP_TYPE_SOCKHASH);
        __uint(max_entries, SOCKOPS_MAP_SIZE);
        __uint(key_size, sizeof(struct socket_4_tuple));
        __uint(value_size, sizeof(uint32_t)); // either __u32 or __u64; the latter (__u64) is to support returning socket cookies to userspace. Returning the struct sock * that the map holds to user-space is neither safe nor useful
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_redir SEC(".maps");

/* This a array map for debug configuration and record bypassed packet number
|-----------|------------------------------------|
|     0     |   0/1 (disable/enable debug info)  |
|-----------|------------------------------------|
|     1     |       bypassed packets number      |
|------------------------------------------------|
*/
// https://docs.kernel.org/bpf/map_array.html
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY); // All array elements are pre-allocated and zero initialized when created
        __uint(max_entries, 2);
        __type(key, uint32_t); // key 就是数组中的索引（index）（因此 key 一定 是整形），因此无需对 key 进行哈希 . All array elements are pre-allocated and zero initialized at init time. Key is an index in array and can only be 4 bytes (32-bit)
        __type(value, uint32_t);  // The value stored can be of any size , however, all array elements are aligned to 8 bytes
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} debug_map SEC(".maps");

static __inline__ void sk_ops_extract4_key(struct bpf_sock_ops *ops,
                struct socket_4_tuple *key)
{
    key->local.ip4 = ops->local_ip4;
    key->local.port = ops->local_port;
    key->remote.ip4 = ops->remote_ip4;
    key->remote.port = bpf_ntohl(ops->remote_port);
}


static __inline__ void sk_msg_extract4_keys(struct sk_msg_md *msg,
                struct socket_4_tuple *proxy_key, struct socket_4_tuple *key)
{
    // 正向4元祖
    proxy_key->local.ip4 = msg->local_ip4;
    // local_port stored in host byte order
    proxy_key->local.port = msg->local_port;
    proxy_key->remote.ip4 = msg->remote_ip4;
    // remote_port Stored in network byte order
    // bpf_ntohl 是一个用于将 32 位整数从网络字节顺序（大端字节序）转换为主机字节顺序（宿主机的字节序）的 eBPF 辅助函数
    // bpf_ntohl 只适用于 32 位整数，如果你需要转换其他数据类型，如 16 位整数或 64 位整数，你需要使用相应的函数，如 bpf_ntohs 和 bpf_ntohll
    proxy_key->remote.port = bpf_ntohl(msg->remote_port);

    // 反向4元祖
    key->local.ip4 = msg->remote_ip4;
    key->local.port = bpf_ntohl(msg->remote_port);
    key->remote.ip4 = msg->local_ip4;
    key->remote.port = msg->local_port;
}
