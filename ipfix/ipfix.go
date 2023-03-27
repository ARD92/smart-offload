/*
Author: Aravind Prabhakar
Description: Ipfix packet decoder for flowoffloader
Sampled packets are used as keep alives to define if 
a filter is receiving packets or not. Everytime a packet 
froma  particular Src -> Dst is received, timestamp is 
recorded. If a packet is not received for >30mins then 
pass the delete RPC call to remove the installed offload
filter
*/
package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"fmt"
	"github.com/google/gopacket/pcap"
	"time"
	"log"
	"encoding/hex"
)

var (
	device      string = "sample1"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)


// IPFIX Template definition
type IpfixTemplate struct {
	IpSrcAddr []byte
	IpDstAddr []byte
	//IpTos uint8
	Protocol layers.IPProtocol
	L4SrcPort uint32
	L4DstPort uint32
	//IcmpType uint8
	//InputSnmp string
	//SrcVlan uint16
	//SrcMask uint8
	//DstMask uint8
	//SrcAs uint16
	//DstAs uint16
	//IpNextHop []byte
	//TcpFlags uint8
	//OutputSnmp string
	//TtlMin uint8
	//TtlMax uint8
	//FlowEndReason uint8
	IpProtoVersion uint8
	//BgpNextHop uint32
	//Direction uint8
	//Dot1qvlanId uint16
	//Dot1qCustVlanId uint16
	//Ipv4Id uint32
	//Bytes uint64
	//Pkts uint16
	//FlowStartMilliSeconds uint16
	//FlowEndMilliSeconds uint16
}

// Flow information to store
var flow IpfixTemplate

// Decoding IPfix template
func decodeIpfix(ifixPayload []byte, ifixTempId []byte) {

}

func decodePacket(packet gopacket.Packet) {
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

	//UdpLayer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("========= UDP Layer ============ \n")
		udp,_ := udpLayer.(*layers.UDP)
		fmt.Println("Source Port: ", udp.SrcPort)
		fmt.Println("Dest Port: ", udp.DstPort)
		fmt.Println("UDP Length: ", udp.Length)
	}

	//IPfix Layer (payload)
	//payload decoded as applicationLayer
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		fmt.Println("decoding Ipfix")
		payload := appLayer.Payload()
		iFixVersion := payload[0:2]
		if strings.Compare(hex.EncodeToString(iFixVersion), "000a") {
			fmt.Println("Decoding IPFIX packet...")
			iFixTempLength := payload[2:4]
			iFixTempTimestamp := payload[4:8]
			iFixTempFlowseq := payload[8:12]
			iFixTempObDomain := payload[12:16]
			TempFlowSetId := payload[16:18]
			TempFlowLen := payload[18:20]
			TempId := payload[20:22]
			fmt.Println(hex.EncodeToString(iFixLength))
			fmt.Println(hex.EncodeToString(flowSetId))
		}
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

