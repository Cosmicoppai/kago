//
// Created by cosmi on 2025/10/01.
//

#ifndef WG_WIN_BINARY_UTILS_H
#define WG_WIN_BINARY_UTILS_H
#define MAX_DNS_LEN 64
#define MAX_DNS 2

typedef struct _InterfaceInfo {
    char InterfaceName[256]; // UTF-8 adapter name
    char DNS1[MAX_DNS_LEN];
    char DNS2[MAX_DNS_LEN];
}InterfaceInfo;

InterfaceInfo get_internet_adapter_info(void);

#endif //WG_WIN_BINARY_UTILS_H

