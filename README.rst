TCP/IP Bypass with eBPF in Istio
================================

This solution aims to bypass TCP/IP stack to accelerate service mesh, it benefits two scenarios:

* p2p communication with sidecar injected
* p2p communication without sidecar injected

This solution is totally independent, which

* does not require changes to linux kernel
* does not require changes to Istio and Envoy (>= v1.10)
* does not require changes to CNI plugin

15%~20% latency decrease is expected for p2p communication on the same host.

System Requirements
~~~~~~~~~~~~~~~~~~~

* Minimal: Distribution with kernel version >= 4.18
* Optimal: Ubuntu 20.04 with Linux 5.4.0-74-generic


Build Docker Image and Load eBPF Program
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Build docker image::

    $ docker build --network=host -t ${IMAGE_NAME} .

#. Load eBPF program via docker command::

    $ docker run --mount type=bind,source=/sys/fs,target=/sys/fs,bind-propagation=rshared --privileged --name tcpip-bypass  ${IMAGE_NAME}

#. Load eBPF program via setting up a deamonset::

    $ kubectl apply -f bypass-tcpip-daemonset.yaml

#. Unload eBPF program via destroying Docker container or deamonset


Debug Log
~~~~~~~~~

#. Enable debug log via modifying the debug MAP::

    $ sudo bpftool map update name debug_map key hex 0 0 0 0  value hex 1 0 0 0

#. Read log from kernel tracepipe::

    $ sudo cat /sys/kernel/debug/tracing/trace_pipe


~# bpftool map dump name debug_map
[{
        "key": 0,
        "value": 1   # 是否使能调试
    },{
        "key": 1,
        "value": 283491    # 数据包成功定向的数量
    }
]


~# bpftool map dump name map_active_estab

~# bpftool map dump name map_proxy

