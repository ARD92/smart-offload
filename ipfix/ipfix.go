/*
Author: Aravind Prabhakar
Description: Ipfix packet decoder 
*/
package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"fmt"
	"github.com/google/gopacket/pcap"
	"time"
	"log"
)

var (
	device      string = "sample1"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)


// Define struct
type IpfixTemplate struct {
	IpSrcAddr []byte
	IpDstAddr []byte
	IpTos uint8
	Protocol layers.IPProtocol
	L4SrcPort uint32
	L4DstPort uint32
	IcmpType uint8
	InputSnmp string
	SrcVlan uint16
	SrcMask uint8
	DstMask uint8
	SrcAs uint16
	DstAs uint16
	IpNextHop []byte
	TcpFlags uint8
	OutputSnmp string
	TtlMin uint8
	TtlMax uint8
	FlowEndReason uint8
	IpProtoVersion uint8
	BgpNextHop uint32
	Direction uint8
	Dot1qvlanId uint16
	Dot1qCustVlanId uint16
	Ipv4Id uint32
	Bytes uint64
	Pkts uint16
	FlowStartMilliSeconds uint16
	FlowEndMilliSeconds uint16
}

func decodePacket(packet gopacket.Packet) {
	//fmt.Println(packet)

	// Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		fmt.Println("========= Ethernet layer ======= \n")
		ethPacket,_ := ethLayer.(*layers.Ethernet)
		fmt.Println("Source Mac: ", ethPacket.SrcMAC)
		fmt.Println("Dest Mac: ", ethPacket.DstMAC)
		fmt.Println("Eth Type: ", ethPacket.EthernetType)
	}

	// Iplayer 
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("========== IP Layer ========== \n")
		ipPacket,_ := ipLayer.(*layers.IPv4)
		fmt.Println("Source IP: ", ipPacket.SrcIP)
		fmt.Println("Dest IP: ", ipPacket.DstIP)
		fmt.Println("Protocol: ", ipPacket.Protocol)
	}
}

func main() {
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {log.Fatal(err) }
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		decodePacket(packet)
	}
}

