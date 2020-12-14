# PassiveMap
packet sniffing network mapper
___
Picture this: you are starting your pen test, fire up your uber l33t machine, run a port scan to discover targets and immediately alert the siem to your nefarious deeds.
Well fear no more! With TerminalJockey's PassiveMap, you can get those sweet, sweet ports without alerting that pesky eye in the sky! Set a packet count and start profiling the network, scope out noisy targets, and silently plan your attack. As kali always reminds us, the quieter you are, the more you can hear.

___

usage:
first, list available interfaces:
- passivemap.exe -list

then either write results to the console or an outfile
- passivemap.exe -iface $id -packetcount $count
- passivemap.exe -iface $id -packetcount $count -outfile $filename
