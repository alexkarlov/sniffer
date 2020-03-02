# Sniffer
A simple sniffer for ip, dns and other kinds of network requests

How to run: 
`sudo make`

It needs root privileges since it attaches to the network interfaces and there is no way to do it without root privileges 
You will see aggregated statistics by `any` network interface ordered by a count of requests (dns) and packet size (ip)

