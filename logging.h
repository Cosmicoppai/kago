//
// Created by CosmicOppai on 2025/10/01.
//

#ifndef WG_WIN_BINARY_LOGGING_H
#define WG_WIN_BINARY_LOGGING_H
#include <sal.h>

#include "wireguard.h"

typedef enum
{
    LOG_INFO, /**< Informational */
    LOG_WARN, /**< Warning */
    LOG_ERR,   /**< Error */
    LOG_DATA   /**< Data */
} LOGGER_LEVEL;

DWORD64 Now(VOID);

DWORD LogError(_In_z_ const WCHAR *Prefix, _In_ DWORD Error);

void Log(_In_ LOGGER_LEVEL Level, _In_z_ const WCHAR *Format, ...);

void CALLBACK ConsoleLogger(_In_ LOGGER_LEVEL Level, _In_ DWORD64 _, _In_z_ const WCHAR *LogLine);

#endif //WG_WIN_BINARY_LOGGING_H