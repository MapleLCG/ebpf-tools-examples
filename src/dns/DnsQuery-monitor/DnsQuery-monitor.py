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