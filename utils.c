#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MAX_DNS_LEN 64
#define MAX_DNS 2

typedef struct _InterfaceInfo {
    char InterfaceName[256];
    char DNS1[MAX_DNS_LEN];
    char DNS2[MAX_DNS_LEN];
}InterfaceInfo;

InterfaceInfo get_internet_adapter_info() {
    InterfaceInfo info = {0};
    DWORD bestIfIndex;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);

    if (GetBestInterface(dest.sin_addr.S_un.S_addr, &bestIfIndex) != NO_ERROR) {
        printf("Failed to get best interface\n");
        return info;
    }

    ULONG outBufLen = 15000;
    IP_ADAPTER_ADDRESSES* adapters = malloc(outBufLen);
    if (!adapters) return info;

    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapters, &outBufLen) != NO_ERROR) {
        free(adapters);
        return info;
    }

    IP_ADAPTER_ADDRESSES* pAddr = adapters;
    while (pAddr) {
        if (pAddr->IfIndex == bestIfIndex) {
            WideCharToMultiByte(
                CP_UTF8,
                0,
                pAddr->FriendlyName,
                -1,
                info.InterfaceName,
                sizeof(info.InterfaceName),
                NULL,
                NULL
            );

            info.DNS1[0] = '\0';
            info.DNS2[0] = '\0';

            IP_ADAPTER_DNS_SERVER_ADDRESS* dns = pAddr->FirstDnsServerAddress;
            int i = 0;
            while (dns && i < 2) {
                char ipstr[INET6_ADDRSTRLEN];
                SOCKADDR* sa = dns->Address.lpSockaddr;

                if (sa->sa_family == AF_INET) {
                    struct sockaddr_in* sa_in = (struct sockaddr_in*)sa;
                    inet_ntop(AF_INET, &sa_in->sin_addr, ipstr, sizeof(ipstr));
                } else if (sa->sa_family == AF_INET6) {
                    struct sockaddr_in6* sa_in6 = (struct sockaddr_in6*)sa;
                    inet_ntop(AF_INET6, &sa_in6->sin6_addr, ipstr, sizeof(ipstr));
                } else {
                    dns = dns->Next;
                    continue;
                }

                if (i == 0) strncpy(info.DNS1, ipstr, MAX_DNS_LEN-1);
                if (i == 1) strncpy(info.DNS2, ipstr, MAX_DNS_LEN-1);
                i++;
                dns = dns->Next;
            }

            break;
        }
        pAddr = pAddr->Next;
    }

    free(adapters);
    return info;
}
