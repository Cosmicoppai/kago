windres omamori.rc omamori_res.o
gcc main.c utils.c omamori_res.o -o omamori.exe -lws2_32 -liphlpapi -lbcrypt -lcrypt32 -lntdll

Write-Output "Compiled Successfully"
#gcc utils.c -o utils.exe -liphlpapi -lws2_32
