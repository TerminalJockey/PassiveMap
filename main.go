package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

type ParseResult struct {
	SrcIP   string
	DstIP   string
	SrcMac  string
	DstMac  string
	Service string
	SrcPort string
	DstPort string
	Payload string
}

var usage string = `PassiveMap: The wire sniffing network mapper
Flags:
-list lists available interfaces, use id to specify interface to use
-iface specifies interface to sniff on
-packetcount specifies number of packets to sniff
-scope specifies what to sniff, internal for all private subnets, all for all traffic
-filter specifies custom network prefixes to filter by
examples:
passivemap.exe -list
passivemap.exe -iface <id> -packetcount <count> -scope internal
passivemap.exe -iface 0 -packetcount 10000 -outfile passive_cap.txt -scope internal -filter 192.168.17.,10.10.10.,172.`

func main() {
	//setup and manage cli flags
	pktCount := flag.Int("packetcount", 1000, "number of packets to sniff")
	listFlag := flag.Bool("list", false, "list interfaces")
	ifaceFlag := flag.Int("iface", 0, "id of interface to sniff on")
	outFileFlag := flag.String("outfile", "", "name of output file")
	helpFlag := flag.Bool("h", false, "displays usage")
	scopeFlag := flag.String("scope", "internal", "set report scope: internal, all")
	filterFlag := flag.String("filter", "", "filter output by subnet prefix")
	flag.Parse()
	if flag.NFlag() < 1 {
		fmt.Println(usage)
		os.Exit(0)
	}
	if *helpFlag == true {
		fmt.Println(usage)
		os.Exit(0)
	}
	if *listFlag == true {
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			log.Println(err)
		}
		for id, iface := range ifaces {
			fmt.Println("id: ", id, "info: ", iface.Name, iface.Addresses)
		}
		os.Exit(0)
	}

	//get interfaces for selection
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Println(err)
	}
	targ := interfaces[*ifaceFlag]
	tout := 30 * time.Second
	handle, err := pcap.OpenLive(targ.Name, 1024, true, tout)
	if err != nil {
		log.Println(err)
	}
	defer handle.Close()
	//manage filtering
	var filter string
	if *scopeFlag == "all" {
		filter = "net 0.0.0.0/0"
	} else if *scopeFlag == "internal" {
		filter = "((src net 172.16.0.0/16 and dst net 172.16.0.0/16) or (src net 192.168.0.0/16 and dst net 192.168.0.0/16) or (src net 10.0.0.0/8 and dst net 10.0.0.0/8))"
	} else {
		fmt.Println(usage)
		os.Exit(0)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Println("Unable to apply filter:", err)
		os.Exit(0)
	}
	fmt.Println("BPF applied:", filter)

	//manage sniffing
	pSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var results []ParseResult
	breakAfter := 0
	fmt.Println("Monitoring...")
	for packet := range pSource.Packets() {
		if breakAfter > *pktCount {
			break
		}
		results = append(results, parsePacket(packet))
		breakAfter++
	}
	combos := makeCombo(results)
	unique := getUnique(combos)
	if *filterFlag != "" {
		fmt.Println("Filtering output based on provided prefixes:", *filterFlag)
		filters := strings.Split(*filterFlag, ",")
		unique = applyReportFilter(unique, filters)
	}
	if *outFileFlag == "" {
		createCLIReport(unique)
	} else {
		createFileReport(unique, *outFileFlag)
	}
}

func parsePacket(packet gopacket.Packet) (parseResult ParseResult) {
	parseResult = ParseResult{}
	//get MACs
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		parseResult.SrcMac = eth.SrcMAC.String()
		parseResult.DstMac = eth.DstMAC.String()
	}
	//get IPs
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		parseResult.SrcIP = ip.SrcIP.String()
		parseResult.DstIP = ip.DstIP.String()
	}
	//get Ports
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		parseResult.SrcPort = tcp.SrcPort.String()
		parseResult.DstPort = tcp.DstPort.String()
	}
	//get payload (experimental for service processing)
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		parseResult.Payload = string(appLayer.Payload())
	}
	return parseResult
}

func getUnique(combos []string) (list []string) {
	keys := make(map[string]bool)
	list = []string{}
	for _, entry := range combos {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func makeCombo(results []ParseResult) (combos []string) {
	for _, result := range results {
		if result.DstPort != "" && result.DstIP != "" {
			concat := result.DstIP + ":" + result.DstPort
			combos = append(combos, concat)
		}
	}
	return combos
}

func createCLIReport(unique []string) {
	//get unique ips
	var ips []string
	for _, val := range unique {
		ip := strings.Split(val, ":")
		ips = append(ips, ip[0])
	}
	ips = getUnique(ips)
	for _, ip := range ips {
		fmt.Println("IP: ", ip)
		var ports []string
		for _, uni := range unique {
			if strings.HasPrefix(uni, ip) == true {
				port := strings.Split(uni, ":")
				ports = append(ports, port[1])
			}
		}
		sort.Strings(ports)
		for _, port := range ports {
			fmt.Println(port)
		}
		fmt.Println()
	}
}

func createFileReport(unique []string, outFileFlag string) {
	out, err := os.Create(outFileFlag)
	if err != nil {
		log.Println(err)
	}
	defer out.Close()
	var ips []string
	for _, val := range unique {
		ip := strings.Split(val, ":")
		ips = append(ips, ip[0])
	}
	ips = getUnique(ips)
	for _, ip := range ips {
		header := "IP: " + ip + "\n"
		out.WriteString(header)
		var ports []string
		for _, uni := range unique {
			if strings.HasPrefix(uni, ip) == true {
				port := strings.Split(uni, ":")
				ports = append(ports, port[1])
			}
		}
		sort.Strings(ports)
		for _, port := range ports {
			out.WriteString(port + "\n")
		}
		out.WriteString("\n")
	}
}

func applyReportFilter(ips []string, filters []string) (filtered []string) {
	for _, ip := range ips {
		for _, filter := range filters {
			if strings.HasPrefix(ip, filter) {
				filtered = append(filtered, ip)
			}
		}
	}
	return filtered
}
