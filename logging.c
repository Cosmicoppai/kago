//
// Created by cosmi on 2025/10/01.
//
#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <math.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum
{
    LOG_INFO, /**< Informational */
    LOG_WARN, /**< Warning */
    LOG_ERR,   /**< Error */
    LOG_DATA   /**< Data */
} LOGGER_LEVEL;

DWORD64 Now(VOID)
{
    LARGE_INTEGER Timestamp;
    NtQuerySystemTime(&Timestamp);
    return Timestamp.QuadPart;
}

void CALLBACK ConsoleLogger(_In_ LOGGER_LEVEL Level, _In_ DWORD64 _, _In_z_ const WCHAR *LogLine)
{
    wchar_t *LevelMarker;
    switch (Level)
    {
    case LOG_INFO:
        LevelMarker = L"INFO";
        break;
    case LOG_WARN:
        LevelMarker = L"WARN";
        break;
    case LOG_ERR:
        LevelMarker = L"ERROR";
        break;
    case LOG_DATA:
        LevelMarker = L"DATA";
        break;
    default:
        return;
    }
    fwprintf(
        stderr,
        L"[%s] %s\n",
        LevelMarker,
        LogLine);
}

DWORD LogError(_In_z_ const WCHAR *Prefix, _In_ DWORD Error)
{
    WCHAR *SystemMessage = NULL, *FormattedMessage = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL,
        HRESULT_FROM_SETUPAPI(Error),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (void *)&SystemMessage,
        0,
        NULL);
    FormatMessageW(
        FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY |
            FORMAT_MESSAGE_MAX_WIDTH_MASK,
        SystemMessage ? L"%1: %3(Code 0x%2!08X!)" : L"%1: Code 0x%2!08X!",
        0,
        0,
        (void *)&FormattedMessage,
        0,
        (va_list *)(DWORD_PTR[]){ (DWORD_PTR)Prefix, (DWORD_PTR)Error, (DWORD_PTR)SystemMessage });
    if (FormattedMessage)
        ConsoleLogger(LOG_ERR, Now(), FormattedMessage);
    LocalFree(FormattedMessage);
    LocalFree(SystemMessage);
    return Error;
}

void Log(_In_ LOGGER_LEVEL Level, _In_z_ const WCHAR *Format, ...)
{
    WCHAR LogLine[0x200];
    va_list args;
    va_start(args, Format);
    _vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, args);
    va_end(args);
    ConsoleLogger(Level, Now(), LogLine);
}