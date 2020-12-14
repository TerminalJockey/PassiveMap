# PassiveMap
packet sniffing network mapper
___
Picture this: you are starting your pen test, fire up your uber l33t machine, run a port scan to discover targets and immediately alert the siem to your nefarious deeds.
Well fear no more! With TerminalJockey's PassiveMap, you can get those sweet, sweet ports without alerting that pesky eye in the sky! Set a packet count and start profiling the network, scope out noisy targets, and silently plan your attack. As kali always reminds us, the quieter you are, the more you can hear.

___
PassiveMap: The wire sniffing network mapper
___
Flags:
- list lists available interfaces, use id to specify interface to use
- iface specifies interface to sniff on 
- packetcount specifies number of packets to sniff
- scope specifies what to sniff, internal for all private subnets, all for all traffic 
- filter specifies custom network prefixes to filter by
___
  examples:
- passivemap.exe -list
- passivemap.exe -iface <id> -packetcount <count> -scope internal 
- passivemap.exe -iface 0 -packetcount 10000 -outfile passive_cap.txt -scope internal -filter 192.168.17.,10.10.10.,172