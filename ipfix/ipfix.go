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
	//"github.com/google/gopacket/layers"
	"fmt"
	"github.com/google/gopacket/pcap"
	"time"
	"log"
	"encoding/hex"
	"strconv"
)

var (
	device      string = "sample1"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)


// Decode bytes and return a dotted val of IP address
func Ipv4Decode(input []byte) string {
	var val [4]string
	for i:=0;i<len(input);i++ {
		hexval := hex.EncodeToString(input[i:i+1])
		dval,_ := strconv.ParseInt(hexval, 16, 64)
		val[i] = strconv.FormatInt(dval,10)
	}
	return val[0]+"."+val[1]+"."+val[2]+"."+val[3]
}

// Decode port bytes and return an int64 value
func PortDecode(input []byte) int64 {
	hexval := hex.EncodeToString(input)
	dval,_ := strconv.ParseInt(hexval, 16, 64)
	return dval
}

type IpfixTempData struct {
	Timestamp string
	ObservationId string
	Version string
	FlowsetId string
	Flowlen string
	Length string
	TemplateId string
	Flowseq string
}

// IPFIX Template definition
type IpfixFlowData struct {
	IpSrcAddr string
	IpDstAddr string
	Protocol int64
	L4SrcPort int64
	L4DstPort int64
	//IpTos uint8
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
	//IpProtoVersion uint8
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

// Template information to store
var temp IpfixTempData

func decodePacket(packet gopacket.Packet) {
	// Flow information to store
	var flow IpfixFlowData
	/*
	// Outer Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		fmt.Println("========= Ethernet layer ======= \n")
		ethPacket,_ := ethLayer.(*layers.Ethernet)
		fmt.Println("Source Mac: ", ethPacket.SrcMAC)
		fmt.Println("Dest Mac: ", ethPacket.DstMAC)
		fmt.Println("Eth Type: ", ethPacket.EthernetType)
	}

	// Outer Iplayer 
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("========== IP Layer ========== \n")
		ipPacket,_ := ipLayer.(*layers.IPv4)
		fmt.Println("Source IP: ", ipPacket.SrcIP)
		fmt.Println("Dest IP: ", ipPacket.DstIP)
		fmt.Println("Protocol: ", ipPacket.Protocol)
	}

	//Outer UdpLayer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("========= UDP Layer ============ \n")
		udp,_ := udpLayer.(*layers.UDP)
		fmt.Println("Source Port: ", udp.SrcPort)
		fmt.Println("Dest Port: ", udp.DstPort)
		fmt.Println("UDP Length: ", udp.Length)
	}*/

	//IPfix Layer (payload) decoding
	//payload decoded as applicationLayer
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload := appLayer.Payload()
		iFixVersion := payload[0:2]
		if hex.EncodeToString(iFixVersion) == "000a" {
			fmt.Println("Decoding IPFIX packet...")
			iFixFlowSetId := hex.EncodeToString(payload[16:18])
			if iFixFlowSetId == "0002" {
				//template packets would be 0002
				fmt.Println("Template packet received \n")
				temp.Version = hex.EncodeToString(iFixVersion)
				temp.Length = hex.EncodeToString(payload[2:4])
				temp.Timestamp = hex.EncodeToString(payload[4:8])
				temp.Flowseq = hex.EncodeToString(payload[8:12])
				temp.ObservationId = hex.EncodeToString(payload[12:16])
				temp.FlowsetId = hex.EncodeToString(payload[16:18])
				temp.Flowlen = hex.EncodeToString(payload[18:20])
				temp.TemplateId = hex.EncodeToString(payload[20:22])
			} else {
				if iFixFlowSetId == temp.TemplateId {
					fmt.Println("Decoding flowdata packet \n")
					//flowsetLen = hex.EncodeToString(payload[18:20])
					//flow.IpSrcAddr = hex.EncodeToString(payload[20:24])
					flow.IpSrcAddr = Ipv4Decode(payload[20:24])
					flow.IpDstAddr = Ipv4Decode(payload[24:28])
					flow.Protocol = PortDecode(payload[29:30])
					flow.L4SrcPort = PortDecode(payload[30:32])
					flow.L4DstPort = PortDecode(payload[32:34])
					fmt.Println("Flow entry: ",flow)
				} else  {
					fmt.Println("cannot decode since Flowset ID is unrecognizable\n")
				}
			}
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

