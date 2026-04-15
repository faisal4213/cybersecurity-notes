# Wireshark Filters for SOC Analysts

## Port Scan Detection
tcp.flags.syn==1 && tcp.flags.ack==0
— Shows SYN packets only. Flood = port scan

## DNS Analysis  
dns.qry.name
— Shows all DNS queries. Look for unusual domains.

dns.qry.name contains ".ru" or dns.qry.name contains ".tk"
— Flag suspicious TLDs

## HTTP Traffic
http.request.method == "POST"
— Shows data being sent. Look for credential exfil.

http.response.code == 200 && http.request.uri contains "admin"
— Successful access to admin pages

## Find Traffic from Specific IP
ip.addr == 192.168.10.250
— Filter all traffic from attacker IP in lab

## Large Packet Size (Possible Exfiltration)
frame.len > 1000 && ip.dst != [your_gateway]
— Unusually large packets going outbound
