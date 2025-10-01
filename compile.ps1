windres kago.rc kago.o
gcc main.c logging.c utils.c kago.o -o kago.exe -lws2_32 -liphlpapi -lbcrypt -lcrypt32 -lntdll

if ($?) {
    Write-Output "Compiled Successfully"
} else {
    Write-Output "Compilation Failed"
}

