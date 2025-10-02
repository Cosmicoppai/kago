## Simple Command Line Wireguard Client for Windows

## To Compile

Run powershell as administrator
```powershell
./compile.ps1
```

## To run the script
```powershell
./kago.exe <private_key> <public_key> <address> <dns> <mtu> <pres_shared_key> <allowed_ips> <endpoint> <persistent_keep_alive>
```

| Parameter                 | Description                                                       |
| ------------------------- |-------------------------------------------------------------------|
| `<private_key>`           | Your WireGuard private key                                        |
| `<public_key>`            | Public key of the WireGuard peer                                  |
| `<address>`               | IP address to assign to the interface                             |
| `<dns>`                   | DNS server to use for the connection  (can be 2 comma sep values) |
| `<mtu>`                   | Maximum Transmission Unit (MTU) for the interface                 |
| `<preshared_key>`         | Optional pre-shared key for additional security                   |
| `<allowed_ips>`           | IP allowed through the VPN, `0.0.0.0` for all traffic             |
| `<endpoint>`              | Remote server address and port (e.g., `example.com:51820`)        |
| `<persistent_keep_alive>` | Interval in seconds to keep the connection alive (0 to disable)   |
