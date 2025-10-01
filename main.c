/* This file is fork of https://git.zx2c4.com/wireguard-nt/tree/example/example.c
 Modified for the use case of Omamori
 */

#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <math.h>
#include <wincrypt.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "wireguard.h"
#include "utils.h"
#include "logging.h"

static WIREGUARD_CREATE_ADAPTER_FUNC *WireGuardCreateAdapter;
static WIREGUARD_OPEN_ADAPTER_FUNC *WireGuardOpenAdapter;
static WIREGUARD_CLOSE_ADAPTER_FUNC *WireGuardCloseAdapter;
static WIREGUARD_GET_ADAPTER_LUID_FUNC *WireGuardGetAdapterLUID;
static WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC *WireGuardGetRunningDriverVersion;
static WIREGUARD_DELETE_DRIVER_FUNC *WireGuardDeleteDriver;
static WIREGUARD_SET_LOGGER_FUNC *WireGuardSetLogger;
static WIREGUARD_SET_ADAPTER_LOGGING_FUNC *WireGuardSetAdapterLogging;
static WIREGUARD_GET_ADAPTER_STATE_FUNC *WireGuardGetAdapterState;
static WIREGUARD_SET_ADAPTER_STATE_FUNC *WireGuardSetAdapterState;
static WIREGUARD_GET_CONFIGURATION_FUNC *WireGuardGetConfiguration;
static WIREGUARD_SET_CONFIGURATION_FUNC *WireGuardSetConfiguration;

#ifndef BCRYPT_ECDH_ALGORITHM
#define BCRYPT_ECDH_ALGORITHM L"ECDH"
#endif

#ifndef BCRYPT_ECC_CURVE_NAME
#define BCRYPT_ECC_CURVE_NAME L"ECCCurveName"
#endif

#ifndef BCRYPT_ECC_CURVE_25519
#define BCRYPT_ECC_CURVE_25519 L"Curve25519"
#endif

InterfaceInfo LOCAL_INTERFACE_INFO = {0};

static HMODULE
InitializeWireGuardNT(void)
{
    HMODULE WireGuardDll =
        LoadLibraryExW(L"wireguard.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!WireGuardDll)
        return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(WireGuardDll, #Name)) == NULL)
    if (X(WireGuardCreateAdapter) || X(WireGuardOpenAdapter) || X(WireGuardCloseAdapter) ||
        X(WireGuardGetAdapterLUID) || X(WireGuardGetRunningDriverVersion) || X(WireGuardDeleteDriver) ||
        X(WireGuardSetLogger) || X(WireGuardSetAdapterLogging) || X(WireGuardGetAdapterState) ||
        X(WireGuardSetAdapterState) || X(WireGuardGetConfiguration) || X(WireGuardSetConfiguration))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(WireGuardDll);
        SetLastError(LastError);
        return NULL;
    }
    return WireGuardDll;
}

static HANDLE QuitEvent;

static BOOL WINAPI
CtrlHandler(_In_ DWORD CtrlType)
{
    switch (CtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        Log(LOG_INFO, L"Cleaning up and shutting down");
        SetEvent(QuitEvent);
        return TRUE;
    default: ;
    }
    return FALSE;
}

typedef struct _WGAllowedIP {
    int address_family;       // AF_INET or AF_INET6
    char ip[64];              // e.g., "192.168.1.2"
    int cidr;                 // e.g., 24
} WGAllowedIP;

typedef struct _WGServer {
    char public_key[WIREGUARD_KEY_LENGTH];   // server public key
    char preshared_key[WIREGUARD_KEY_LENGTH]; // preshared key
    char host[64];                            // server host (IP or domain)
    unsigned short port;                      // server port
    int persistent_keepalive;                 // keepalive interval
    WGAllowedIP allowed_ip;                   // allowed IP for peer
} WGServer;

typedef struct _WGInterface {
    char private_key[WIREGUARD_KEY_LENGTH]; // private key
    int mtu;                                // MTU
    char client_ip[64];                     // local IP
    int client_prefix_length;               // CIDR
} WGInterface;

typedef struct _WGArgs {
    WGInterface iface;
    WGServer server;
    char dns[64];          // DNS server
    char dns2[64];
} WGArgs;

int is_valid_ipv4(const char *ip_str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_str, &(sa.sin_addr)) == 1;
}

_Return_type_success_(return != FALSE)
static BOOL
updateDNS(char dns1[], char dns2[]) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "netsh interface ip set dns name=\"%s\" static %s primary",
             LOCAL_INTERFACE_INFO.InterfaceName, dns1);
    int cmd_success = system(cmd);
    if (cmd_success != 0) {
        Log(LOG_ERR, L"Failed to update DNS1");
        return FALSE;
    }

    if ( strcmp(dns1, dns2) == 0 ) {
        Log(LOG_INFO, L"DNS1 and DNS2 are identical, Skipping setting DNS2");
        return TRUE;
    }

    snprintf(cmd, sizeof(cmd),
             "netsh interface ip add dns name=\"%s\" %s index=2",
             LOCAL_INTERFACE_INFO.InterfaceName, dns2);
    cmd_success = system(cmd);
    if (cmd_success != 0) {
        Log(LOG_ERR, L"Failed to update DNS2");
        return FALSE;
    }

    system("ipconfig /flushdns");

    Log(LOG_INFO, L"New DNS applied and flushed");

    return TRUE;
}

_Return_type_success_(return != FALSE)
static BOOL
revertDNS() {
    if ( strlen(LOCAL_INTERFACE_INFO.DNS1) > 0 && strlen(LOCAL_INTERFACE_INFO.DNS2) > 0 ) {
        return updateDNS(LOCAL_INTERFACE_INFO.DNS1, LOCAL_INTERFACE_INFO.DNS2);
    }
    return TRUE;

}

_Return_type_success_(return != FALSE)
static BOOL
parse_args(const int argc, char **argv, WGArgs *wg_args) {
    if (argc < 10) {
        Log(LOG_ERR, L"Wrong number of arguments", GetLastError());
        return FALSE;
    }
    BYTE decoded[WIREGUARD_KEY_LENGTH];
    DWORD len = sizeof(decoded);


    // parse private and public key

    CryptStringToBinaryA(argv[1], 0, CRYPT_STRING_BASE64, decoded, &len, NULL, NULL);
    memcpy(wg_args->iface.private_key, decoded, WIREGUARD_KEY_LENGTH);

    len = sizeof(decoded);
    CryptStringToBinaryA(argv[2], 0, CRYPT_STRING_BASE64, decoded, &len, NULL, NULL);
    memcpy(wg_args->server.public_key, decoded, WIREGUARD_KEY_LENGTH);


    // parse Client Address
    char *client_address = argv[3];
    char *slash = strchr(client_address, '/');
    if (!slash) {
        Log(LOG_ERR, L"Wrong client address", GetLastError());
        return FALSE;
    }
    char client_ip[64];
    char client_prefix_length_char[3];
    size_t client_ip_len = slash - client_address;
    if (client_ip_len >= sizeof(client_ip)) {
        client_ip_len = sizeof(client_ip) - 1;
    }
    memcpy(client_ip, client_address, client_ip_len);
    client_ip[client_ip_len] = '\0';
    memcpy(wg_args->iface.client_ip, client_ip, sizeof(wg_args->iface.client_ip)-1);


    strncpy(client_prefix_length_char, slash+1, sizeof(client_prefix_length_char) - 1);
    char *endptr;
    long client_prefix_length = strtol(client_prefix_length_char, &endptr, 10);
    if (*endptr != '\0' || client_prefix_length < 0 || client_prefix_length > 32) {
        Log(LOG_ERR, L"Invalid prefix length", GetLastError());
        return FALSE;
    }
    wg_args->iface.client_prefix_length = client_prefix_length;


    // parse DNS
    char *token = strtok(argv[4], ",");
    int count = 0;
    char dns_array[2][65] = {"10.66.66.1", "10.66.66.1"};

    while (token != NULL && count < MAX_DNS) {
        if (!is_valid_ipv4(token)) {
            Log(LOG_ERR, L"Invalid DNS IP: %hs", token);
        } else {
            strncpy(dns_array[count], token, sizeof(dns_array[count]) - 1);
            dns_array[count][sizeof(dns_array[count]) - 1] = '\0';
        }
        count++;
        if ( count == 2 ) {
            break;
        }
        token = strtok(NULL, ",");
    }

    strncpy(wg_args->dns, dns_array[0], sizeof(wg_args->dns) - 1);
    strncpy(wg_args->dns2, dns_array[1], sizeof(wg_args->dns2) - 1);

    // parse mtu
    char *mtu_str = argv[5];
    int mtu = strtol(mtu_str, &endptr, 10);
    if (*endptr != '\0' || mtu < 0 || mtu > 2000) {
        Log(LOG_ERR, L"Invalid MTU", GetLastError());
        return FALSE;
    }
    wg_args->iface.mtu = mtu;


    // parse preshared key
    len = sizeof(decoded);
    CryptStringToBinaryA(argv[6], 0, CRYPT_STRING_BASE64, decoded, &len, NULL, NULL);
    memcpy(wg_args->server.preshared_key, decoded, WIREGUARD_KEY_LENGTH);


    // parse allowed ips
    char *allowed_ips = argv[7];
    int cidr;

    if (sscanf(allowed_ips, "%63[^/]/%d", wg_args->server.allowed_ip.ip, &cidr) != 2) {
        Log(LOG_ERR, L"Address must contain '/'", GetLastError());
        return FALSE;
    }

    if (!is_valid_ipv4(wg_args->server.allowed_ip.ip)) {
        Log(LOG_ERR, L"Invalid IP address", GetLastError());
        return FALSE;
    }

    if (cidr < 0 || cidr > 32) {
        Log(LOG_ERR, L"Invalid Allowed CIDR Range", GetLastError());
        return FALSE;
    }
    wg_args->server.allowed_ip.cidr = cidr;
    wg_args->server.allowed_ip.address_family = AF_INET;


    // parse endpoint and port
    char *_endpoint = argv[8];
    char host[64];
    char port_char[16];

    char *colon = strchr(_endpoint, ':'); // find the ':'
    if (!colon) {
        Log(LOG_ERR, L"Invalid endpoint string", GetLastError());
        return 1;
    }

    size_t host_len = colon - _endpoint;
    if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
    memcpy(host, _endpoint, host_len);
    host[host_len] = '\0';

    if (!is_valid_ipv4(host)) {
        Log(LOG_ERR, L"Invalid Endpoint host address", GetLastError());
        return FALSE;
    }

    strncpy(port_char, colon + 1, sizeof(port_char) - 1);
    port_char[sizeof(port_char) - 1] = '\0';

    long port = strtol(port_char, &endptr, 10);
    if (*endptr != '\0' || port < 0 || port > 65535) {
        Log(LOG_ERR, L"Invalid Server Port", GetLastError());
        return FALSE;
    }

    strncpy(wg_args->server.host, host, sizeof(wg_args->server.host) - 1);
    wg_args->server.port = port;


    wg_args->server.persistent_keepalive = atoi(argv[9]);

    return TRUE;
}

int main(const int argc, char **argv) {

    WGArgs wg_args = {0};
    if ( !parse_args(argc, argv, &wg_args) ) {
        Log(LOG_ERR, L"Failed to parse arguments", GetLastError());
        return 1;
    }

    DWORD LastError;
    WSADATA WsaData;
    if (WSAStartup(MAKEWORD(2, 2), &WsaData))
        return LogError(L"Failed to initialize Winsock", GetLastError());
    HMODULE WireGuard = InitializeWireGuardNT();
    if (!WireGuard)
    {
        LastError = LogError(L"Failed to initialize WireGuardNT", GetLastError());
        goto cleanupWinsock;
    }
    WireGuardSetLogger(ConsoleLogger);
    Log(LOG_INFO, L"WireGuardNT library loaded");

    LOCAL_INTERFACE_INFO = get_internet_adapter_info();

    struct
    {
        WIREGUARD_INTERFACE Interface;
        WIREGUARD_PEER Server;
        WIREGUARD_ALLOWED_IP AllowedIp;
    } Config = { .Interface = { .Flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY, .PeersCount = 1 },
                 .Server = { .Flags = WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_HAS_ENDPOINT | WIREGUARD_PEER_HAS_PRESHARED_KEY,
                                 .AllowedIPsCount = 1 },
                 .AllowedIp = { .AddressFamily = AF_INET} };


    memcpy(Config.Server.PublicKey, wg_args.server.public_key, WIREGUARD_KEY_LENGTH);
    memcpy(Config.Interface.PrivateKey, wg_args.iface.private_key, WIREGUARD_KEY_LENGTH);
    memcpy(Config.Server.PresharedKey, wg_args.server.preshared_key, WIREGUARD_KEY_LENGTH);


    Config.AllowedIp.AddressFamily = wg_args.server.allowed_ip.address_family;
    inet_pton(Config.AllowedIp.AddressFamily, wg_args.server.allowed_ip.ip, &Config.AllowedIp.Address.V4);
    Config.AllowedIp.Cidr = (BYTE)wg_args.server.allowed_ip.cidr;

    Config.Server.PersistentKeepalive = wg_args.server.persistent_keepalive;

    Config.Server.Endpoint.si_family = AF_INET;
    Config.Server.Endpoint.Ipv4.sin_family = AF_INET;
    Config.Server.Endpoint.Ipv4.sin_port = htons(wg_args.server.port);
    InetPtonA(AF_INET, wg_args.server.host, &Config.Server.Endpoint.Ipv4.sin_addr);

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    InetPtonA(AF_INET, wg_args.iface.client_ip, &AddressRow.Address.Ipv4.sin_addr);
    AddressRow.OnLinkPrefixLength = wg_args.iface.client_prefix_length;
    AddressRow.DadState = IpDadStatePreferred;

    DWORD Bytes = sizeof(Config.Server.PublicKey);

    QuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!QuitEvent)
    {
        LastError = LogError(L"Failed to create event", GetLastError());
        goto cleanupWireGuard;
    }
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        LastError = LogError(L"Failed to set console handler", GetLastError());
        goto cleanupQuit;
    }

    GUID ExampleGuid = { 0xdeadc001, 0xbeef, 0xbabe, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    WIREGUARD_ADAPTER_HANDLE Adapter = WireGuardCreateAdapter(L"Omamori", L"Tunnel-1", &ExampleGuid);
    if (!Adapter)
    {
        LastError = GetLastError();
        LogError(L"Failed to create adapter", LastError);
        goto cleanupQuit;
    }

    if (!WireGuardSetAdapterLogging(Adapter, WIREGUARD_ADAPTER_LOG_ON))
        LogError(L"Failed to enable adapter logging", GetLastError());

    DWORD Version = WireGuardGetRunningDriverVersion();
    Log(LOG_INFO, L"WireGuardNT v%u.%u loaded", (Version >> 16) & 0xff, (Version >> 0) & 0xff);

    WireGuardGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);
    MIB_IPFORWARD_ROW2 DefaultRoute = { 0 };
    InitializeIpForwardEntry(&DefaultRoute);
    DefaultRoute.InterfaceLuid = AddressRow.InterfaceLuid;
    DefaultRoute.DestinationPrefix.Prefix.si_family = AF_INET;
    DefaultRoute.NextHop.si_family = AF_INET;
    DefaultRoute.Metric = 0;
    LastError = CreateIpForwardEntry2(&DefaultRoute);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LogError(L"Failed to set default route", LastError);
        goto cleanupAdapter;
    }
    LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        LogError(L"Failed to set IP address", LastError);
        goto cleanupAdapter;
    }
    MIB_IPINTERFACE_ROW IpInterface = { 0 };
    InitializeIpInterfaceEntry(&IpInterface);
    IpInterface.InterfaceLuid = AddressRow.InterfaceLuid;
    IpInterface.Family = AF_INET;
    LastError = GetIpInterfaceEntry(&IpInterface);
    if (LastError != ERROR_SUCCESS)
    {
        LogError(L"Failed to get IP interface", LastError);
        goto cleanupAdapter;
    }
    IpInterface.UseAutomaticMetric = FALSE;
    IpInterface.Metric = 0;
    IpInterface.NlMtu = wg_args.iface.mtu;
    IpInterface.SitePrefixLength = 0;
    LastError = SetIpInterfaceEntry(&IpInterface);
    if (LastError != ERROR_SUCCESS)
    {
        LogError(L"Failed to set metric and MTU", LastError);
        goto cleanupAdapter;
    }

    Log(LOG_INFO, L"Setting configuration and adapter up");
    if (!WireGuardSetConfiguration(Adapter, &Config.Interface, sizeof(Config)) ||
        !WireGuardSetAdapterState(Adapter, WIREGUARD_ADAPTER_STATE_UP))
    {
        LastError = LogError(L"Failed to set configuration and adapter up", GetLastError());
        goto cleanupAdapter;
    }

    updateDNS(wg_args.dns, wg_args.dns2);

    do
    {
        Bytes = sizeof(Config);
        if (!WireGuardGetConfiguration(Adapter, &Config.Interface, &Bytes) || !Config.Interface.PeersCount)
        {
            LastError = LogError(L"Failed to get configuration", GetLastError());
            goto cleanupAdapter;
        }

        wchar_t log_buffer[256];
        swprintf(log_buffer, sizeof(log_buffer) / sizeof(wchar_t),
            L"upload: %llu download: %llu", Config.Server.RxBytes, Config.Server.TxBytes);

        Log(LOG_DATA, log_buffer);

    } while (WaitForSingleObject(QuitEvent, 1000) == WAIT_TIMEOUT);

cleanupAdapter:
    WireGuardCloseAdapter(Adapter);
    revertDNS();
cleanupQuit:
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    CloseHandle(QuitEvent);
cleanupWireGuard:
    FreeLibrary(WireGuard);
cleanupWinsock:
    WSACleanup();
    return LastError;
}