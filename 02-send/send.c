#include <stdio.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>

#define ENABLE_SEND 1  	// 启用发送

// ？？为什么不取整
#define NUM_MBUFS (4096 - 1)
#define BURST_SIZE 32

#if ENABLE_SEND
// 源、目的 MAC
static uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
static uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];
// 源、目的 IP
static uint32_t g_src_ip;
static uint32_t g_dst_ip;
// 源、目的端口
static uint16_t g_src_port;
static uint16_t g_dst_port;
#endif

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
	const int num_tx_queues = 1; 	// tx 队列数量为 1
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
	// 1.3.4 配置 eth0 第 0 号接收（rx）队列的结点数量（128）
	if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId),
		NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}
#if ENABLE_SEND
	// 1.3.5 配置发送队列
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), 
		&txq_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}
#endif
	// 1.3.6 启动 eth0 端口
	if (rte_eth_dev_start(gDpdkPortId) < 0) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
}

// 3.1.4 封包
static void ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) 
{
	// 3.1.4.1 组装 eth 头
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, g_dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	// 3.1.4.2 组装 ip 头
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45; 	// v4、头长度 20B
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; 		// ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = g_src_ip;
	ip->dst_addr = g_dst_ip;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);	// 计算 checksum
	// 3.1.4.3 组装 udp 头
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = g_src_port;
	udp->dst_port = g_dst_port;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);
	// 3.1.4.4 组装数据
	rte_memcpy((uint8_t *)(udp + 1), data, udplen);
	// 3.1.4.5 计算 UDP checksum
	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
	

	struct in_addr addr;
	addr.s_addr = g_src_ip;
	printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(g_src_port));
	addr.s_addr = g_dst_ip;
	printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(g_dst_port));
}

// 3.1 组包并发包
static struct rte_mbuf *ng_send(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) 
{
	// 3.1.1 计算包总长，udph --> 8B; iph --> 20B; mach --> 14B
	const unsigned total_len = length + 42;	
	// 3.1.2 发包需要从 mbuf_pool 中申请
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);	
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;
	// 3.1.3 拿到数据头
	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);
	// 3.1.4 封包
	ng_encode_udp_pkt(pktdata, data, total_len);

	return mbuf;
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
	// 1.4 获取 eth0 mac，用于发包
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)g_src_mac);

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

#if ENABLE_SEND
				// 2.2.5 将收包的源 mac、源目的 IP、源目的端口留存，用于回包
				rte_memcpy(g_dst_mac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				rte_memcpy(&g_src_ip, &iphdr->dst_addr, sizeof(uint32_t));
				rte_memcpy(&g_dst_ip, &iphdr->src_addr, sizeof(uint32_t));
				rte_memcpy(&g_src_port, &udphdr->dst_port, sizeof(uint16_t));
				rte_memcpy(&g_src_port, &udphdr->src_port, sizeof(uint16_t));
#endif				
				
				// 2.2.6 udp 包末尾设置修改为 '\0'，防止打印时越界
				uint16_t length = ntohs(udphdr->dgram_len);
				*((char *)udphdr + length) = '\0';
				// 2.2.7 输出：源 ip + 源端口
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));
				// 2.2.8 输出：目的 ip + 目的端口 + data
				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port),
					(char *)(udphdr + 1)); // udphdr 不做类型转换，+1 直接偏移掉头部
#if ENABLE_SEND
				/*****************
				3. 发送回包，包内为接收数据
				******************/
				// 3.1 组包并发包
				struct rte_mbuf *txbuf = ng_send(mbuf_pool, (uint8_t *)(udphdr + 1), length);
				// 3.2 通过 eth0 的第 0 号发包队列发送 1 个包
				rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
				// 3.3 释放发包内容
				rte_pktmbuf_free(txbuf);
#endif
				/*****************
				4. 使用后释放内存
				******************/
				rte_pktmbuf_free(mbufs[i]);
			}
		}
	}

	return 0;
}
