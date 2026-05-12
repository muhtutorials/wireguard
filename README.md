# How Wireguard works

Client 45.78.34.102 [1-->] Server 189.210.55.89 [2-->] Kernel (NAT) [3-->] Internet 8.8.8.8

1. UDP outer packet: src 45.78.34.102, dst 189.210.55.89
   Encrypted inner packet: src 10.0.0.2, dst 8.8.8.8

2. Decrypted inner packet: src 10.0.0.2, dst 8.8.8.8

3. Decrypted inner packet: src 189.210.55.89, dst 8.8.8.8


Internet 8.8.8.8 [1-->] Kernel (NAT) [2-->] Server 189.210.55.89 [3-->] Client 45.78.34.102

1. Packet: src 8.8.8.8, dst 189.210.55.89

2. Packet: src 8.8.8.8, dst 10.0.0.2

3. UDP outer packet: src 189.210.55.89, dst 45.78.34.102
   Encrypted inner packet: src 8.8.8.8, dst 10.0.0.2
