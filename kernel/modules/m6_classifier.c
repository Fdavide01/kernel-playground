#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M6 Project");
MODULE_DESCRIPTION("Destination IP Classifier - Advanced Level");
MODULE_VERSION("1.2");

// Netfilter hook structures for IPv4 and IPv6
static struct nf_hook_ops ipv4_ops;
static struct nf_hook_ops ipv6_ops;

// Counters for packet classifications
static unsigned int count_class_a = 0;
static unsigned int count_class_b = 0;
static unsigned int count_class_c = 0;
static unsigned int count_ipv6    = 0;

// Thresholds to simulate traffic shaping for each class
#define THRESHOLD_A 15
#define THRESHOLD_B 10
#define THRESHOLD_C 7
#define THRESHOLD_IPV6 5

// Hook function for IPv4 packets
static unsigned int ipv4_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;

    if (!skb)
        return NF_ACCEPT;

    // Retrieve IPv4 header
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    // Extract first byte (octet) of destination IP address
    __be32 daddr = ntohl(iph->daddr);
    u8 first_octet = (daddr >> 24) & 0xFF;

    printk(KERN_INFO "M6: Dest IP: %pI4 - First octet: %u\n", &iph->daddr, first_octet);

    // Classify and increment the corresponding counter
    if (first_octet >= 1 && first_octet <= 127) {
        count_class_a++;
        printk(KERN_INFO "M6: IPv4 Class A destination\n");
        if (count_class_a > THRESHOLD_A)
            printk(KERN_INFO "M6: [SIMULATION] Traffic shaping triggered for Class A\n");
    } else if (first_octet >= 128 && first_octet <= 191) {
        count_class_b++;
        printk(KERN_INFO "M6: IPv4 Class B destination\n");
        if (count_class_b > THRESHOLD_B)
            printk(KERN_INFO "M6: [SIMULATION] Traffic shaping triggered for Class B\n");
    } else if (first_octet >= 192 && first_octet <= 223) {
        count_class_c++;
        printk(KERN_INFO "M6: IPv4 Class C destination\n");
        if (count_class_c > THRESHOLD_C)
            printk(KERN_INFO "M6: [SIMULATION] Traffic shaping triggered for Class C\n");
    } else {
        printk(KERN_INFO "M6: IPv4 Unknown Class\n");
    }

    return NF_ACCEPT;
}

// Hook function for IPv6 packets
static unsigned int ipv6_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    count_ipv6++;
    printk(KERN_INFO "M6: IPv6 packet detected\n");

    if (count_ipv6 > THRESHOLD_IPV6)
        printk(KERN_INFO "M6: [SIMULATION] Traffic shaping triggered for IPv6\n");

    return NF_ACCEPT;
}

// Function to show statistics in /proc/m6_stats
static int m6_stats_show(struct seq_file *m, void *v)
{
    seq_printf(m, "IPv4 Class A: %u\n", count_class_a);
    seq_printf(m, "IPv4 Class B: %u\n", count_class_b);
    seq_printf(m, "IPv4 Class C: %u\n", count_class_c);
    seq_printf(m, "IPv6 Packets: %u\n", count_ipv6);
    return 0;
}

// Called when the /proc file is opened
static int m6_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, m6_stats_show, NULL);
}

// File operations for /proc/m6_stats
static const struct proc_ops m6_proc_fops = {
    .proc_open    = m6_stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

// Module initialization
static int __init m6_init(void)
{
    // Configure IPv4 hook
    ipv4_ops.hook = ipv4_hookfn;
    ipv4_ops.hooknum = NF_INET_LOCAL_OUT;
    ipv4_ops.pf = PF_INET;
    ipv4_ops.priority = NF_IP_PRI_FIRST;

    // Configure IPv6 hook
    ipv6_ops.hook = ipv6_hookfn;
    ipv6_ops.hooknum = NF_INET_LOCAL_OUT;
    ipv6_ops.pf = PF_INET6;
    ipv6_ops.priority = NF_IP6_PRI_FIRST;

    // Register Netfilter hooks
    nf_register_net_hook(&init_net, &ipv4_ops);
    nf_register_net_hook(&init_net, &ipv6_ops);

    // Create /proc/m6_stats entry
    proc_create("m6_stats", 0, NULL, &m6_proc_fops);

    printk(KERN_INFO "M6: classifier module loaded\n");
    return 0;
}

// Module cleanup
static void __exit m6_exit(void)
{
    // Unregister hooks and remove /proc entry
    nf_unregister_net_hook(&init_net, &ipv4_ops);
    nf_unregister_net_hook(&init_net, &ipv6_ops);
    remove_proc_entry("m6_stats", NULL);

    printk(KERN_INFO "M6: classifier module unloaded\n");
}

module_init(m6_init);
module_exit(m6_exit);
