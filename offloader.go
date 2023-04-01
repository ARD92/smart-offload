/*
Author: Aravind Prabhakar
Version: v1.0
Description: Flow offloader on a service chained topology. This app
will listen to syslog session Inits and closes from vSRX and offload the
flow on to MX.
*/

package main

import (
	"context"
	"fmt"
	auth "jnx/jet/auth"
	jnx "jnx/jet/common"
	fw "jnx/jet/firewall"
	"strings"
	"time"
	"log"
	"syscall"
	"os"
	"strconv"
	"github.com/akamensky/argparse"
	"unicode/utf8"
	"hash/fnv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"golang.org/x/crypto/ssh/terminal"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"encoding/hex"
)

const (
	TYPE            = "udp"         //protocol type
	SESS_CREATE     = "RT_FLOW_SESSION_CREATE"
	SESS_CLOSE      = "RT_FLOW_SESSION_CLOSE"
	VALID_SESS_TIME = 30 //seconds
	VALID_FILTER_TIME = 120 //seconds
	TIMEOUT         = 30
	INDEX           = 0
	ROUTE_TABLE	= "TEST-CUSTOMER-VRF.inet.0" // userconfig for customer vrf
	INTERFACE_NAME	= "ge-0/0/5.0" //user config for reverse filter
	SERVICE_FILTER	= "FLOW_OFFLOAD"
	SERVICE_FILTER_REVERSE	= "FLOW_OFFLOAD_REVERSE"
)

var (
	device      string = "jet"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

// session values which would be stored in maps
type sessionValues struct {
	source_ip   string
	source_port string
	dest_ip     string
	dest_port   string
	//protocol string;
	session_time string
}

// initiate JET session with junos
type Session struct {
	// jetConn holds the gRPC connection made to cRPD
	jetConn *grpc.ClientConn

	// ribClient is the handle to send gRPC requests JUNOS PRPD RIB service.
	cliClient fw.FirewallClient

	// cliContext is used for gRPC requests to RIB service.
	cliContext context.Context
}

var junos Session

func connectJET(addr string, juser string, jpass string) error {
	if junos.jetConn != nil {
		return nil
	}
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(time.Duration(TIMEOUT)*time.Second))
	if err != nil {
		fmt.Println("did not connect: %s", err)
	}
	junos.jetConn = conn
	clientId := "trafficoffload"
	md := metadata.Pairs("client-id", clientId)
	login := auth.NewLoginClient(conn)
	loginReq := &auth.LoginRequest{
		UserName: juser,
		Password: jpass,
		ClientId: clientId,
	}
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	if _, err := login.LoginCheck(junos.cliContext, loginReq); err != nil {
		fmt.Println("Error authenticating..\n")
	}
	fmt.Println("connected to grpc")
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	junos.cliClient = fw.NewFirewallClient(conn)
	return nil
}


// remove UTF-8 character
func RemoveLastChar(str string) string {
	for len(str) > 0 {
		_, size := utf8.DecodeLastRuneInString(str)
		return str[:len(str)-size]
	}
	return str
}


func RemoveFirstChar(s string) string {
	_, i := utf8.DecodeRuneInString(s)
	return s[i:]
}


//generate Hash
func HashString(str string) string {
	h := fnv.New32a()
	h.Write([]byte(str))
	s := strconv.FormatUint(uint64(h.Sum32()),10)
	return s
}


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


var sessionVals sessionValues

// Map to store {flow1: (sip,dip,sport, dport, protocol, time), flow2:(), flow3:().....}
var sessTable = make(map[string]sessionValues)

// Parse the flow to grab 5 tuple information
func decodeSyslog(buffer string) (sessionValues, string) {
	datasplit := strings.Split(buffer, " ")
	sessType := strings.TrimRight(datasplit[5], " ")
	if strings.Compare(sessType, SESS_CREATE) == 0 {
		//fmt.Println("session create received")
		sessionVals.session_time = datasplit[1]
		for i := 7; i <= 10; i++ {
			val := strings.Split(datasplit[i], "=")
			switch val[0] {
			case "source-address":
				sessionVals.source_ip = RemoveFirstChar(RemoveLastChar(val[1]))
			case "source-port":
				sessionVals.source_port = RemoveFirstChar(RemoveLastChar(val[1]))
			case "destination-address":
				sessionVals.dest_ip = RemoveFirstChar(RemoveLastChar(val[1]))
			case "destination-port":
				sessionVals.dest_port = RemoveFirstChar(RemoveLastChar(val[1]))
			}
		}
	} else if strings.Compare(sessType, SESS_CLOSE) == 0 {
		//fmt.Println("session close received..")
		sessionVals.session_time = datasplit[1]
		for i := 7; i <= 10; i++ {
			val := strings.Split(datasplit[i], "=")
			switch val[0] {
			case "source-address":
				sessionVals.source_ip = RemoveFirstChar(RemoveLastChar(val[1]))
			case "source-port":
				sessionVals.source_port = RemoveFirstChar(RemoveLastChar(val[1]))
			case "destination-address":
				sessionVals.dest_ip = RemoveFirstChar(RemoveLastChar(val[1]))
			case "destination-port":
				sessionVals.dest_port = RemoveFirstChar(RemoveLastChar(val[1]))
			}
		}
	}
	return sessionVals, sessType
}

// Template information to store
var temp IpfixTempData

func decodeIpfix(payload []byte) string {
	var iflow IpfixFlowData
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
				iflow.IpSrcAddr = Ipv4Decode(payload[20:24])
				iflow.IpDstAddr = Ipv4Decode(payload[24:28])
				iflow.Protocol = PortDecode(payload[29:30])
				iflow.L4SrcPort = PortDecode(payload[30:32])
				iflow.L4DstPort = PortDecode(payload[32:34])
				fmt.Println("Flow entry: ",iflow)
			} else {
				fmt.Println("Unable to decode IPfix packet \n")
			}
		}
	} else {
		fmt.Println("Not an IPFIX packet, skipping decoding.. \n")
	}
	return iflow.IpSrcAddr + iflow.IpDstAddr + strconv.Itoa(int(iflow.L4SrcPort)) + strconv.Itoa(int(iflow.L4DstPort))
}

// Map to store {flow1: (sip,dip,sport, dport, protocol, time), flow2:(), flow3:().....}
var offloadTable = make(map[string]sessionValues)
//validate flow and offload based on session time threshold

func programFlow(hflow string) {
	time.Sleep(VALID_SESS_TIME * time.Second)
	val, ok := sessTable[hflow]
	if ok {
		log.Println(time.Now(),"valid session time elapsed and flow is still active. adding redirection on MX\n")
		offloadTable[hflow] = val
		addFlow(SERVICE_FILTER, hflow, val.source_ip, val.dest_ip, val.source_port, val.dest_port)
		addFlow(SERVICE_FILTER_REVERSE, hflow, val.dest_ip, val.source_ip, val.dest_port, val.source_port)
		log.Println("added entry to offload table")
	} else {
		log.Println("flow doesnt exist. skip programming.. \n")
	}
}


func decodePacket(packet gopacket.Packet) {
	// Flow information to store
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
	}*/

	//Outer UdpLayer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	var uDestPort layers.UDPPort
	if udpLayer != nil {
		fmt.Println("========= UDP Layer ============ \n")
		udp,_ := udpLayer.(*layers.UDP)
		fmt.Println("Source Port: ", udp.SrcPort)
		fmt.Println("Dest Port: ", udp.DstPort)
		fmt.Println("UDP Length: ", udp.Length)
		uDestPort = udp.DstPort
	}
	if uDestPort == 514 {
		fmt.Println("syslog packet")
		log.Println("received syslog packet....")
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			// syslog string occurs 42B after UDP payload
			syslogString := string(payload)
			fmt.Println(syslogString)
			vals, sessType := decodeSyslog(syslogString)
			if strings.Compare(sessType, SESS_CREATE) == 0 {
				flow := vals.source_ip + vals.dest_ip + vals.source_port + vals.dest_port
				hflow := HashString(flow)
				sessTable[hflow] = vals
				go programFlow(hflow)
				log.Println(time.Now(), "added flowinfo to session table\n")

			} else if strings.Compare(sessType, SESS_CLOSE) == 0 {
				flow := vals.source_ip + vals.dest_ip + vals.source_port + vals.dest_port
				hflow := HashString(flow)
				time.Now()
				delete(sessTable, hflow)
				log.Println(time.Now(),"Received either session close due to session close msg or due to session time out from vSRX. Deleted flowinfo from session table\n")
			}
		}

	} else if uDestPort == 45000 {
		fmt.Println("ipfix packet")
		//IPfix Layer (payload) decoding
		//payload decoded as applicationLayer
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			flow := decodeIpfix(payload)
			hflow := HashString(flow)
			// check if flow exists in offload table 
			val, ok := offloadTable[hflow]
			if ok {
				fmt.Println("Flow exists in offload table.. retain it", val)
			} else {
				fmt.Println("Flow does not exist in offload table..", val)
			}

		}
	}
}



// program default accept term so that it can fall back to cli filter
func programDefaultTerm(filtername string) {
	cntName := "COUNT-JET-ACCEPT-ALL"
	Action := &fw.FilterTermInetAction {
		ActionsNt: &fw.FilterTermInetNonTerminatingAction {Count: &fw.ActionCounter {CounterName: cntName}},
		ActionT: &fw.FilterTermInetTerminatingAction {TerminatingAction: &fw.FilterTermInetTerminatingAction_Accept {Accept: true}},
	}
	Adj := &fw.FilterAdjacency { Type: fw.FilterAdjacencyType_TERM_AFTER, TermName: "(null)" }
	var filterTermSlice []*fw.FilterTerm
	filterTerm := &fw.FilterTerm {
		FilterTerm : &fw.FilterTerm_InetTerm {
			InetTerm : &fw.FilterInetTerm { 
				TermName: "JET-ACCEPT-ALL",
				TermOp: fw.FilterTermOperation_TERM_OPERATION_ADD,
				Adjacency: Adj,
				Actions: Action,
			},
		},
	}
	filterTermSlice = append(filterTermSlice, filterTerm)
	// Filter family type : 1 (Ipv4), 2(IPv6)
	// Filter type: 1(Classic), 0 (Invalid)
	addreq := &fw.FilterAddRequest{
		Name: filtername,
		Type: fw.FilterTypes_TYPE_CLASSIC,
		Family: fw.FilterFamilies_FAMILY_INET,
		TermsList: filterTermSlice,
	}
	log.Println(addreq)
	resp, err := junos.cliClient.FilterAdd(junos.cliContext, addreq)
	if err != nil {
		log.Println("Failed to program jet-offload default-term")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		log.Println("failed to program jet-offload default-term")
	} else {
		log.Println("successfully programmed jet-offload default-term", resp)
	}
}

// Filter binding . Currently only IPv4 supported
func filterBind(filtername string, bindtype string, bindval string){
	var bindreq *fw.FilterObjBindAddRequest
	if bindtype == "interface" {
		bindreq = &fw.FilterObjBindAddRequest {
			Filter: &fw.Filter {Name: filtername, Family:fw.FilterFamilies_FAMILY_INET},
			ObjType: fw.FilterBindObjType_BIND_OBJ_TYPE_INTERFACE,
			BindObject: &fw.FilterBindObjPoint {
				BindPoint: &fw.FilterBindObjPoint_InterfaceName {
					InterfaceName: bindval,
				},
			},
			BindDirection: fw.FilterBindDirection_BIND_DIRECTION_INPUT,
			BindFamily: fw.FilterFamilies_FAMILY_INET,
		}
	} else if bindtype == "fwdtable" {
		bindreq = &fw.FilterObjBindAddRequest {
			Filter: &fw.Filter {Name: filtername, Family:fw.FilterFamilies_FAMILY_INET},
			ObjType: fw.FilterBindObjType_BIND_OBJ_TYPE_FWD_TABLE,
			BindObject: &fw.FilterBindObjPoint {
				BindPoint: &fw.FilterBindObjPoint_ForwardingTable {
					ForwardingTable: bindval,
				},
			},
			BindDirection: fw.FilterBindDirection_BIND_DIRECTION_INPUT,
			BindFamily: fw.FilterFamilies_FAMILY_INET,
		}
	}
	resp, err := junos.cliClient.FilterBindAdd(junos.cliContext, bindreq)
	if err != nil {
		log.Println("Failed to bind filter\n")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		log.Println("failed to bind filter to routing instance or interface\n")
	} else {
		log.Println("Successfully bound filter to routing-instance or interface\n")
	}
}

// program flow to MX as JET filter
func addFlow(filtername string, name string, src_ip string, dst_ip string, src_port string, dst_port string) {
	idstport,_ := strconv.Atoi(dst_port)
	isrcport,_ := strconv.Atoi(src_port)
	udstport := uint32(idstport)
	usrcport := uint32(isrcport)
	dstAddr := &fw.MatchIpAddress {
		Addr: &jnx.IpAddress {
			AddrFormat: &jnx.IpAddress_AddrString {
				AddrString: dst_ip,
			},
		},
		PrefixLength: 32,
		Operation: fw.MatchOperation_OP_EQUAL,
	}
	srcAddr := &fw.MatchIpAddress {
		Addr: &jnx.IpAddress {
			AddrFormat: &jnx.IpAddress_AddrString {
				AddrString: src_ip,
			},
		},
		PrefixLength: 32,
		Operation: fw.MatchOperation_OP_EQUAL,
	}
	dstPort := &fw.MatchPort {
		Min: udstport,
		Max: udstport,
		Operation: fw.MatchOperation_OP_EQUAL,
	}
	srcPort := &fw.MatchPort {
		Min: usrcport,
		Max: usrcport,
		Operation: fw.MatchOperation_OP_EQUAL,
	}
	var dstAddrSlice []*fw.MatchIpAddress
	var srcAddrSlice []*fw.MatchIpAddress
	var dstPortSlice []*fw.MatchPort
	var srcPortSlice []*fw.MatchPort
	dstAddrSlice = append(dstAddrSlice, dstAddr)
	dstPortSlice = append(dstPortSlice, dstPort)
	srcAddrSlice = append(srcAddrSlice, srcAddr)
	srcPortSlice = append(srcPortSlice, srcPort)
	Match := &fw.FilterTermMatchInet {
		//To do: Add protocol if needed
		Ipv4DstAddrs: dstAddrSlice,
		Ipv4SrcAddrs: srcAddrSlice,
		DstPorts: dstPortSlice,
		SrcPorts: srcPortSlice,
	}
	cntName := "COUNT-"+name
	Action := &fw.FilterTermInetAction {
		ActionsNt: &fw.FilterTermInetNonTerminatingAction {Count: &fw.ActionCounter {CounterName: cntName}, Sample: true},
		ActionT: &fw.FilterTermInetTerminatingAction {TerminatingAction: &fw.FilterTermInetTerminatingAction_Accept {Accept: true}},
	}
	Adj := &fw.FilterAdjacency { Type: fw.FilterAdjacencyType_TERM_AFTER, TermName: "JET-ACCEPT-ALL" } // JET-ACCEPT-ALL will be placed after definining term
	var filterTermSlice []*fw.FilterTerm
	filterTerm := &fw.FilterTerm {
		FilterTerm : &fw.FilterTerm_InetTerm {
			InetTerm : &fw.FilterInetTerm { 
				TermName: "OFFLOAD_"+name,
				TermOp: fw.FilterTermOperation_TERM_OPERATION_ADD,
				Adjacency: Adj,
				Matches: Match,
				Actions: Action,
			},
		},
	}
	filterTermSlice = append(filterTermSlice, filterTerm)
	// Filter family type : 1 (Ipv4), 2(IPv6)
	// Filter type: 1(Classic), 0 (Invalid)
	addreq := &fw.FilterModifyRequest{
		Name: filtername,
		Type: fw.FilterTypes_TYPE_CLASSIC,
		Family: fw.FilterFamilies_FAMILY_INET,
		TermsList: filterTermSlice,
	}
	log.Println(addreq)
	resp, err := junos.cliClient.FilterModify(junos.cliContext, addreq)
	if err != nil {
		log.Println("Failed to program jet-offload filter")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		log.Println("failed to program jet-offload filter")
	} else {
		log.Println("successfully programmed", resp)
	}
}

// delete flow on MX from JET filters
/*func delFlow(name string) {
	var filterTermSlice []*fw.FilterTerm
	filterTerm := &fw.FilterInetTerm {
		TermName: "OFFLOAD_"+name,
		TermOp: 2 // term delete,
	}
	filterTermSlice = append(filterTermSlice, filterTerm)
	// Filter family type : 1 (Ipv4), 2(IPv6)
	// Filter type: 1(Classic), 0 (Invalid)
	output := &mgmt.FilterModifyRequest{
		Name: "FLOW_OFFLOAD",
		Types: 1,
		Family: 1,
		TermsList: filterTermSlice,
	}
	fmt.Println(output)
	resp, err := junos.cliClient.FilterModify(junos.cliContext, output)
	if err != nil {
		fmt.Println("Failed to delete flow")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("failed to delete flow")
	} else {
		fmt.Println("successfully deleted the flow", resp)
	}
}*/




func main() {
	logs, logerr := os.OpenFile("offloader.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
	if logerr != nil {
		log.Fatalf("Error opening file: %v", logerr)
	}
	defer logs.Close()
	log.SetOutput(logs)

	parser := argparse.NewParser("Required-args", "\n============\ntraffic-offloader\n============")
	log.Println("connected to host ...")
	//port := parser.String("p", "port", &argparse.Options{Required: true, Help: "Port number to bind app to"})
	jip := parser.String("J", "jetip", &argparse.Options{Required: true, Help: "Jet host IP "})
	jport := parser.String("P", "jetport", &argparse.Options{Required: true, Help: "Jet host port"})
	juser := parser.String("u", "user", &argparse.Options{Required: true, Help: "user name for jet host"})
	jpass := parser.String("w", "password", &argparse.Options{Required: false, Help: "password for jet host"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	} else {
		if *jpass == "" {
			log.Print("Enter Password: ")
			bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatalf("Err: %v\n", err)
			}
			*jpass = string(bytePassword)
		}

		//establish connection to  MX over gRPC channel
		connectJET(*jip + ":" + *jport, *juser, *jpass)

		//program default accept term to fail over to cli filter for unmatched packets.
		programDefaultTerm(SERVICE_FILTER)
		programDefaultTerm(SERVICE_FILTER_REVERSE)
		filterBind(SERVICE_FILTER,"fwdtable", ROUTE_TABLE )
		filterBind(SERVICE_FILTER_REVERSE, "interface", INTERFACE_NAME)
		// handle packets
		handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
		if err != nil {log.Fatal(err) }
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			decodePacket(packet)
		}

	}
}
