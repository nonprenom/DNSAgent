# DNSAgent

A C program for Linux that captures DNS response packets and displays the
resolved domain names along with their corresponding IP addresses (A, AAAA, and
CNAME records) in a clear, human-readable format.

## Files

- dnsagent.c : the full program
- Makefile : a simple makefile to build and clean dnsagent.c
- test.sh : a bash script I used to tests

## Build

You need the pcap-dev package installed
`# sudo apt-get install libpcap-dev`

Then, run make in the directory
`# make`

## Execute

dnsagent requires 1 parameter : the interface to listen to.
for example:
`# ./dnsagent wlp0s20f3`
You can see all the interfaces with the command 
`# ip a`

### Note
- Since dnsagent configures and uses the pcap library to sniff raw data on the specified interface, it requires root privileges.
- I used this command to build and test the application:
`# make dnsagent && clear && sudo ./dnsagent wlp0s20f3`
- dnsagent runs in a continuous loop and prints all the DNS responses to the console until you exit with Ctrl+C.
- dnsagent supports both small UDP DNS responses and large TCP ones.

## Sample output
The program waits for dns responses on the interface and shows, for each response:

```
[a timestamp][the protocol UDP or TCP]
	[resolved name A][record 1][record 2]...[record N]
	[resolved name B][record 1][record 2]...[record N]
	...
	[resolved name Z][record 1][record 2]...[record N]`
```
### Sample
```
Initialization of DNS Agent on interface [wlp0s20f3]
Setting pcap buffer size to 4194304 bytes...
Listening for DNS responses (udp and src port 53 or tcp and src port 53) on wlp0s20f3...
[2025-11-27 10:26:36][TCP]
        [www.google.com][A:142.251.140.100]
        [www.google.com][AAAA:2a00:1450:4002:400::2004]
[2025-11-27 10:26:37][TCP]
        [securingsam.com][A:162.159.135.42]
[2025-11-27 10:26:37][TCP]
        [drive.erwan.my.to][A:109.67.6.132]
[2025-11-27 10:26:37][TCP]
        [yahoo.com][A:74.6.231.21]
        [yahoo.com][A:98.137.11.163]
        [yahoo.com][A:74.6.231.20]
        [yahoo.com][A:98.137.11.164]
        [yahoo.com][A:74.6.143.25]
        [yahoo.com][A:74.6.143.26]
        [yahoo.com][AAAA:2001:4998:24:120d::1:0]
        [yahoo.com][AAAA:2001:4998:124:1507::f001]
        [yahoo.com][AAAA:2001:4998:24:120d::1:1]
        [yahoo.com][AAAA:2001:4998:44:3507::8001]
        [yahoo.com][AAAA:2001:4998:44:3507::8000]
        [yahoo.com][AAAA:2001:4998:124:1507::f000]
[2025-11-27 10:27:15][UDP]
        [dns.google][AAAA:2001:4860:4860::8844]
        [dns.google][AAAA:2001:4860:4860::8888]
[2025-11-27 10:27:15][UDP]
        [dns.google][A:8.8.8.8]
        [dns.google][A:8.8.4.4]
[2025-11-27 10:27:17][UDP]
        [vscode-sync.trafficmanager.net][CNAME:vscode-sync.trafficmanager.net.vscode-sync-frc-01.azurewebsites.net]
        [vscode-sync-frc-01.azurewebsites.net][CNAME:vscode-sync-frc-01.azurewebsites.net.waws-prod-par-031.sip.azurewebsites.windows.net]
        [waws-prod-par-031.sip.azurewebsites.windows.net][CNAME:waws-prod-par-031.sip.azurewebsites.windows.net.waws-prod-par-031-7d07.francecentral.cloudapp.azure.com]
[2025-11-27 10:27:17][UDP]
        [vscode-sync.trafficmanager.net][CNAME:vscode-sync.trafficmanager.net.vscode-sync-frc-01.azurewebsites.net]
        [vscode-sync-frc-01.azurewebsites.net][CNAME:vscode-sync-frc-01.azurewebsites.net.waws-prod-par-031.sip.azurewebsites.windows.net]
        [waws-prod-par-031.sip.azurewebsites.windows.net][CNAME:waws-prod-par-031.sip.azurewebsites.windows.net.waws-prod-par-031-7d07.francecentral.cloudapp.azure.com]
[2025-11-27 10:27:17][UDP]
        [vscode-sync.trafficmanager.net][CNAME:vscode-sync.trafficmanager.net.vscode-sync-frc-01.azurewebsites.net]
        [vscode-sync-frc-01.azurewebsites.net][CNAME:vscode-sync-frc-01.azurewebsites.net.waws-prod-par-031.sip.azurewebsites.windows.net]
        [waws-prod-par-031.sip.azurewebsites.windows.net][CNAME:waws-prod-par-031.sip.azurewebsites.windows.net.waws-prod-par-031-7d07.francecentral.cloudapp.azure.com]
        [waws-prod-par-031-7d07.francecentral.cloudapp.azure.com][A:20.111.1.3]
[2025-11-27 10:29:50][UDP]
        [deb.nodesource.com][CNAME:deb.nodesource.com.deb.nodesource.com.cdn.cloudflare.net]
        [deb.nodesource.com.cdn.cloudflare.net][A:104.20.45.190]
        [deb.nodesource.com.cdn.cloudflare.net][A:172.66.150.169]
[2025-11-27 10:29:50][UDP]
        [deb.nodesource.com][CNAME:deb.nodesource.com.deb.nodesource.com.cdn.cloudflare.net]
        [deb.nodesource.com.cdn.cloudflare.net][AAAA:2606:4700:10::6814:2dbe]
        [deb.nodesource.com.cdn.cloudflare.net][AAAA:2606:4700:10::ac42:96a9]
[2025-11-27 10:29:50][UDP]
        [debian.interhost.co.il][A:185.37.148.245]
[2025-11-27 10:29:50][UDP]
        [debian.interhost.co.il][AAAA:2a03:ff40:dcbe:ab1a::2]
```
## Challenges
- The DNS payload format, specifically the string compression/optimization. (I encountered a similar technique while working on the ELF format at CISCO.)

- I initially thought the DNS protocol was UDP-only, until I requested a full DNS response (e.g., for yahoo.com). I then learned about the truncated UDP packet followed by the larger TCP packets.

- The size of the pcap kernel buffer became too small to handle very fast and full DNS queries. For this, I increased the size of the kernel ring buffer to 4MB and added multiple checks during parsing to skip invalid packets.

- Note on Embedded Optimization
A larger pcap buffer is acceptable on a standard PC. However, if this program were designed for an embedded system, I would implement an additional custom ring buffer within the application and dedicate a new thread for parsing and printing the results.

The proposed integration architecture would be as follows:

A new thread dedicated to parsing packets and printing results. This thread would wait for new entries in the ring buffer using a conditional variable.

The pcap_loop thread: Its callback would perform a very fast operation: simply pushing the packet to the ring buffer and notifying the conditional variable.
