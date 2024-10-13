#include <stdio.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>

// ？？为什么不取整
#define NUM_MBUFS (4096 - 1)

#define BURST_SIZE 32

int gDpdkPortId = 0;
static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

// 1.3 初始化并启动端口
static void ng_init_port(struct rte_mempool *mbuf_pool) 
{
	// 1.3.1 获取有效端口数量，即 igb_uio 绑定的端口数量
	uint16_t nb_sys_ports = rte_eth_dev_count_avail(); 
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}
	// 1.3.2 获取 eth0 设备的（默认）信息
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);
	// 1.3.3 配置 eth0 的 rx、tx 队列数量
	const int num_rx_queues = 1;
	const int num_tx_queues = 0;
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
	// 1.3.4 配置 eth0 第 0 号接收（rx）队列的结点数量（128）
	if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId),
		NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}
	// 1.3.5 启动 eth0 端口
	if (rte_eth_dev_start(gDpdkPortId) < 0) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
}

// 0. 简单发送接收
int main(int argc, char *argv[])
{
	/*****************
	1. 环境初始化
	******************/

	// 1.1 DPDK 环境初始化
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}
	// 1.2 DPDK 内存池设置，一个 DPDK 进程确定一个 mempool
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", 
		NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}
	// 1.3 初始化并启动端口
	ng_init_port(mbuf_pool);
	
	/*****************
	2. 接收数据包
	******************/

	while (1) {
		// 2.1 从 eth0 的 0 号接收队列取回数据
		//     mbufs 是数组指针，指向空间为 mempool 中的 mbuf
		//     一次最多取 BURST_SIZE 个
		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
		// 2.2 解析接收到的数据包
		unsigned int i = 0;
		for (i = 0; i < num_recvd; i++) {
			// 2.2.1 解析二层 eth 头，收到的包是 eth 包
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
			// 2.2.2 暂不处理非 ipv4 包
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}
			// 2.2.3 解析三层 ip 头
			struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], 
				struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			// 2.2.4 解析四层 udp 头
			if (iphdr->next_proto_id == IPPROTO_UDP) {
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)((unsigned char *)iphdr + sizeof(struct rte_ipv4_hdr));
				// 2.2.5 udp 包末尾设置修改为 '\0'，防止打印时越界
				uint16_t length = ntohs(udphdr->dgram_len);
				*((char *)udphdr + length) = '\0';
				// 2.2.6 输出：源 ip + 源端口
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), udphdr->src_port);
				// 2.2.7 输出：目的 ip + 目的端口 + data
				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d, %s\n", inet_ntoa(addr), udphdr->dst_port,
					(char *)(udphdr + 1)); // udphdr 不做类型转换，+1 直接偏移掉头部
				// 2.2.8 使用后释放内存
				rte_pktmbuf_free(mbufs[i]);
			}
		}
	}

	return 0;
}
