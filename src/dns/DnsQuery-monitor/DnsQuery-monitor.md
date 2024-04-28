# ebpf-监控进程DNS查询

## DNS查询介绍

DNS，全称Domain Name System，负责将域名解析为IP地址。

在互联网上，公网IP是每台公网主机的门牌号，有了IP才能够访问到对应的公网主机。IP地址形如：111.111.111.111，由四段三位数字组成，这导致其非常不容易记忆。因此，为了方便，域名（Domain）诞生了。

域名，可以把它看做IP的昵称，它和IP具有对应关系，通常具有一定的意义，因此十分方便记忆。例如，百度的域名为：baidu.com，而百度的IP为：39.156.66.10。前者显然更方便我们使用和记忆。

在我们使用域名访问网站的时候，会先进行DNS查询这个操作。DNS查询，简单来说就是将域名解析为IP地址的过程。使用域名，必然绕不过DNS查询。



## DNS数据包

DNS报文格式如下，前12字节为DNS报文首部，紧接着就是我们的查询字段。查询字段里存放着我们需要查询的域名。

![1](.\1.png)

这里介绍一下查询字段的格式，假设我们查询的域名为：baidu.com

那么这个域名在查询字段是以这样的形式存在的：

05 62 61 69 64 75 03 63 6f 6d 00

其中，05是位数，代表着baidu的长度，62 ... 75是baidu的十六进制ASCII码。03代表着com的长度，63 6f 6d是com的十六进制ASCII码。00代表查询字段终止。

总结一下，我们可以将域名按点分段：

组分1.组分2.组分3

那么查询字段的组成为

(组分1的长度)(组分1的ASCII)(组分2的长度)(组分2的ASCII)(组分3的长度)(组分3的ASCII)



## 恶意软件

当你的主机不幸感染了恶意软件，有时候这些恶意软件会与攻击者准备好的恶意地址进行通信。当我们通过恶意域名检测定位到受害主机是，需要进行应急响应，以解决风险。虽然我们知道了哪台主机处于风险当中，但处理恶意软件却并不是一件简单的事情。通常，恶意软件会把自己伪装起来，并且将自身存放到一些难以注意的角落，更有甚者仅存在于内存当中。

因此，如果有方法能够快速定位到恶意软件的进程信息以及路径的话，对处置受害主机将有一定的帮助。

## ebpf

ebpf是一种linux的内核技术，它能够在不修改内核的情况下，动态的插入我们的代码，以获取我们想要的信息。ebpf中的kprobe允许我们挂载到内核函数上，获取其传入参数，之后我们可以将参数通过某种方式传递回用户空间。

### 内核函数：udp_sendmsg

当程序进行DNS查询时，通常会用到UDP协议。在linux网络协议栈中，udp_sendmsg函数有着关键的地位。

其函数原型为：

```c
int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
```

这里不对该函数做过多的介绍，我们将目光放在第二个参数：struct msghdr *msg

简单来说，在DNS查询的情况下，这个结构体存放着我们的DNS报文，获取报文头部指针和榜文长度的代码如下：

```c
const struct iovec * iov = msg -> msg_iter.iov;
// 获取iov结构体中的iov_base和iov_len字段
void __user *iov_base = iov->iov_base; //报文头指针
u32 iov_len = iov->iov_len;//报文长度
```

根据以上全部内容，我们准备使用ebpf技术来监控Linux主机上进程DNS查询情况

## 实验环境

1.BCC框架（Python）

2.WSL2 Ubuntu 22.04.3 LTS (GNU/Linux 5.15.137.3-microsoft-standard-WSL2 x86_64)



## 代码实现

```python
#!/usr/bin/env python3
from bcc import BPF,Table
from socket import htonl, inet_ntoa
from struct import pack

C_BPF_KPROBE = """
#include <net/sock.h>
#include <linux/uio.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>



struct DNSinfo {
    char comm[16];
    char domain[64];

    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;

    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_PERF_OUTPUT(dns_events);


int trace_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
  
    // 通常来说，DNS查询使用53端口
    // 13568 = ntohs(53);
    if (sport == 13568 || dport == 13568) {
        // 获取基本信息（ip、端口、pid等）
        u32 saddr = sk->sk_rcv_saddr;
        u32 daddr = sk->sk_daddr;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // UDP --> 17
        struct DNSinfo key = {.proto = 17};
        key.saddr = htonl(saddr);
        key.daddr = htonl(daddr);
        key.sport = sport;
        key.dport = htons(dport);

        key.pid = pid_tgid >> 32;
        key.tgid = (u32)pid_tgid;
        key.uid = (u32)uid_gid;
        key.gid = uid_gid >> 32;
        
        //获取进程名字
        bpf_get_current_comm(key.comm, 64);


        struct msghdr * msg = (struct msghdr *)PT_REGS_PARM2(ctx);
        const struct iovec * iov = msg -> msg_iter.iov;
        // 获取iov结构体中的iov_base和iov_len字段
        void __user *iov_base = iov->iov_base;
        u32 iov_len = iov->iov_len;
        // 确保长度不超过domain的大小
        u32 len = iov_len < sizeof(key.domain) ? iov_len : sizeof(key.domain) - 1;

        //iov_base + 12，跳过DNS报文前12字节，直奔域名字段
        bpf_probe_read(&key.domain, len, iov_base+12);


        //将获取到的数据通过PerfTable传递出去
        dns_events.perf_submit(ctx,&key,sizeof(key));
        
    }
    return 0;
}

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;

    if (sport == 13568 || dport == 13568) {

        u32 saddr = sk->sk_rcv_saddr;
        u32 daddr = sk->sk_daddr;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();

        struct DNSinfo key = {.proto = 6};
        key.saddr = htonl(saddr);
        key.daddr = htonl(daddr);
        key.sport = sport;
        key.dport = htons(dport);

        key.pid = pid_tgid >> 32;
        key.tgid = (u32)pid_tgid;
        key.uid = (u32)uid_gid;
        key.gid = uid_gid >> 32;
        bpf_get_current_comm(key.comm, 64);


        struct msghdr * msg = (struct msghdr *)PT_REGS_PARM2(ctx);
        const struct iovec * iov = msg -> msg_iter.iov;

        void __user *iov_base = iov->iov_base;
        u32 iov_len = iov->iov_len;

        u32 len = iov_len < sizeof(key.domain) ? iov_len : sizeof(key.domain) - 1;

        bpf_probe_read(&key.domain, len, iov_base+12);
        
        dns_events.perf_submit(ctx,&key,sizeof(key));
    }
    return 0;
}
"""

#################################################################################
#query to domain
#这个函数的作用是将查询字段转换为可视的域名
#但这个函数我偷了个懒，因此没办法处理组分长度过长的域名
#请自行修改
def qtod(query):
    # 将查询内容转换为可打印的字符串
    query = query.decode('unicode_escape')
    # 初始化域名字符串
    domain = ''
    # 分割字符串并转换
    while query:
        length = ord(query[0])  # 获取段的长度
        if length == 0:  # 如果长度为0，则结束
            break
        domain += query[1:length+1] + '.'  # 添加段到域名
        query = query[length+1:]  # 移除已处理的部分
    return domain.rstrip('.')  

def ntoh(num):
        ip = inet_ntoa(pack("I", htonl(num)))

        return ip



###########################################################
def print_dns(cpu, data, size):
    event = bpf_kprobe["dns_events"].event(data)
    ProtoType = {17:"UDP", 6:"TCP"}
    
    comm = event.comm.decode()
    pid = event.pid
    domain = qtod(event.domain)
    saddr = ntoh(event.saddr)
    daddr = ntoh(event.daddr)
    print("%-16s %-8s %-24s %-3s %-16s %-5s %-16s %-5s"%(
        comm, pid, domain, ProtoType[event.proto], 
        saddr, event.sport, daddr, event.dport))
    '''
    The program is running. Press Ctrl-C to abort.
    COMM             PID      DOMAIN                   PROTO  SIP              SPORT DIP              DPORT
    ping             877      baidu.com                UDP    192.168.221.75   41143 192.168.208.1    53
    '''




#BPF初始化
bpf_kprobe = BPF(text=C_BPF_KPROBE)


# UDP:
bpf_kprobe.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
# TCP:
bpf_kprobe.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")


print('The program is running. Press Ctrl-C to abort.')
print("%-16s %-8s %-24s %-5s %-16s %-5s %-16s %-5s"%(
    "COMM","PID","DOMAIN","PROTO","SIP","SPORT","DIP","DPORT"))
bpf_kprobe["dns_events"].open_perf_buffer(print_dns)

while True:
    try:
        bpf_kprobe.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

## 效果

![2](.\2.png)



## 预告

下次文章，我们将介绍如何获取进程的存在路径及cmdline