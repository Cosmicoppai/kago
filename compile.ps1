windres omamori.rc omamori_res.o
gcc main.c omamori_res.o -o omamori.exe -lws2_32 -liphlpapi -lbcrypt -lcrypt32 -lntdll

Write-Output "Compiled Successfully"

