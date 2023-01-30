/*
Author: Aravind Prabhakar
Version: v1.0
Description: Flow offloader using management IPs to inject flowspec redirect to IP action

To do:
1. use an inmemory db (redis/sqllite3) instead of maintaining a DS
2. Handle > 1 flow for add and del flows

*/

package main

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"net"
	"strings"
	"time"
	//"gitlab.com/tymonx/go-formatter/formatter"
	jnx "jnx/jet/common"
	//mgmt "jnx/jet/mgmt"
	auth "jnx/jet/auth"
	rtg "jnx/jet/routing"
)

const (
	HOST            = "192.171.1.2" //host to bind app to
	PORT            = 514           //port to bind app to
	TYPE            = "udp"         //protocol type
	SESS_CREATE     = "RT_FLOW_SESSION_CREATE:"
	SESS_CLOSE      = "RT_FLOW_SESSION_CLOSE:"
	VALID_SESS_TIME = 3
	JET_HOST        = "192.167.1.6"
	JET_PORT        = "50051"
	JET_USER        = "root"
	JET_PASSWD      = "juniper123"
	TIMEOUT         = 30
	//INDEX = 0
	ACTION             = "DISCARD" //DISCARD or REDIRECT_TO_VRF
	REDIRECT_IP        = "10.1.1.1"
	REDIRECT_COMMUNITY = "target:13979:999"
	COMMUNITY          = "13979:999"
	PNH_IP             = "10.1.1.1"
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
	//cliClient mgmt.ManagementClient

	//pRPD flowspec to handle gRPC
	bgpClient rtg.BgpClient

	// cliContext is used for gRPC requests to RIB service.
	cliContext context.Context
}

var junos Session

func connectJET(addr string) error {
	if junos.jetConn != nil {
		return nil
	}
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(time.Duration(TIMEOUT)*time.Second))
	if err != nil {
		fmt.Println("did not connect: %s", err)
	}
	junos.jetConn = conn
	clientId := "traffic-offload"
	md := metadata.Pairs("client-id", clientId)
	login := auth.NewAuthenticationClient(conn)
	loginReq := &auth.LoginRequest{
		Username: JET_USER,
		Password: JET_PASSWD,
		ClientId: clientId,
	}
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	if reply, err := login.Login(junos.cliContext, loginReq); err != nil {
		fmt.Println("Error authenticating..\n")
	} else if reply.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("Failed to authenticate\n")
	}
	fmt.Println("connected to grpc")
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	//junos.cliClient = mgmt.NewManagementClient(conn)
	junos.bgpClient = rtg.NewBgpClient(conn)
	return nil
}

//func addFlow(name string, src_ip string, dst_ip string, action string) {
func addFlow(src_ip string, dst_ip string, action string) {
	// save name for deleting purposes
	fmt.Println(src_ip, dst_ip)
	dstIP := &jnx.IpAddress{AddrFormat: &jnx.IpAddress_AddrString{AddrString: dst_ip}}
	srcIP := &jnx.IpAddress{AddrFormat: &jnx.IpAddress_AddrString{AddrString: src_ip}}
	// flowspec match conditions
	flowMatch := &rtg.FlowspecAddress{
		Destination:     dstIP,
		DestPrefixLen:   32,
		Source:          srcIP,
		SourcePrefixLen: 32,
		//IpProtocols:
		//SrcPorts: srcPorts,
		//DestPorts: dstPorts,
	}
	flowRt := &rtg.RoutePrefix{
		RoutePrefixAf: &rtg.RoutePrefix_InetFlowspec{InetFlowspec: flowMatch},
	}
	// communities defn
	var communitySlice []*rtg.Community
	communities := &rtg.Community{Community: COMMUNITY}
	communitySlice = append(communitySlice, communities)
	communitySlices := &rtg.Communities{Communities: communitySlice}

	key := &rtg.RouteMatch{
		DestPrefix:    flowRt,
		DestPrefixLen: 32,
		Table:         &rtg.RouteTable{RouteTableFormat: &rtg.RouteTable_Name{Name: &rtg.RouteTableName{Name: "inetflow.0"}}},
		Protocol:      rtg.RouteProtoType_PROTO_BGP_STATIC,
		Cookie:        999, //hardcoded
		Communities:   communitySlices,
	}
	var rtentrySlice []*rtg.RouteEntry
	var flowspecRtData *rtg.FlowspecRouteData
	// if action= redirect to vrf
	if action == "REDIRECT_TO_VRF" {
		flowspecRtData = &rtg.FlowspecRouteData{
			RedirectInstRtComm: REDIRECT_COMMUNITY,
		}
	} else if action == "DISCARD" {
		flowspecRtData = &rtg.FlowspecRouteData{
			Discard: true,
		}
	}

	var nhSlice []*jnx.IpAddress
	nhIP := &jnx.IpAddress{AddrFormat: &jnx.IpAddress_AddrString{AddrString: PNH_IP}}
	nhSlice = append(nhSlice, nhIP)
	rtentry := &rtg.RouteEntry{
		Key: key,
		//RoutePreference: UInt32Value(10),
		//LocalPreference: 1000,
		ProtocolNexthops: nhSlice,
		AddrFamilyData:   &rtg.AddressFamilySpecificData{RouteDataAf: &rtg.AddressFamilySpecificData_FlowspecData{FlowspecData: flowspecRtData}},
		RouteFlags:       &rtg.RouteFlags{UseNexthopFictitious: true},
	}
	rtentrySlice = append(rtentrySlice, rtentry)
	updrequest := &rtg.RouteUpdateRequest{
		Routes: rtentrySlice,
	}
	fmt.Println(updrequest)
	resp, err := junos.bgpClient.RouteAdd(junos.cliContext, updrequest)
	if err != nil {
		fmt.Println("Failed to add flowspec route")
	} else {
		fmt.Println("successfully programmed", resp)
	}
}

// Program valid flows for redirection on MX
// will check if session table still has flow active
func programFlow(flow string) {
	fmt.Println("entering program flow")
	time.Sleep(VALID_SESS_TIME * time.Second)
	// check sesstable if exists
	val, ok := sessTable[flow]
	if ok {
		fmt.Println("30 seconds elapsed and flow is still active. adding redirection on MX\n")
		fmt.Println(val)
		addFlow(val.source_ip, val.dest_ip, ACTION)
	} else {
		fmt.Println("flow doesnt exist. skip programming.. \n")
	}
}

// BGP initialization
func BgpInit(bgpconn rtg.BgpClient) error {
	initRequest := &rtg.InitializeRequest{}
	resp, err := junos.bgpClient.Initialize(junos.cliContext, initRequest)
	if err != nil {
		fmt.Println("Failed to initialize BGP session")
	} else {
		fmt.Println("successfully initialized", resp)
	}
	return err
}

var sessionVals sessionValues

// Map to store {flow1: (sip,dip,sport, dport, protocol, time), flow2:(), flow3:().....}
var sessTable = make(map[string]sessionValues)

// Store the flowspec name
var flowspecMap = make(map[string]string)

func main() {
	fmt.Println("connected...")
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: PORT, Zone: ""})
	buf := make([]byte, 1024)
	//establish connection to  MX over gRPC channel
	connectJET(JET_HOST + ":" + JET_PORT)
	// initialize BGP client
	BgpInit(junos.bgpClient)
	fmt.Println("finished initialization")
	//receive data from udp socket
	for {
		fmt.Println("waiting to receive data..... ")
		data, _, _ := serverConn.ReadFromUDP(buf)
		fmt.Println(data)
		bufdata := string(buf[0:data])
		datasplit := strings.SplitAfter(bufdata, " ")
		//sessType := datasplit[5]
		session_time := datasplit[0] + datasplit[1] + datasplit[2]
		if strings.Compare(strings.TrimRight(datasplit[5], " "), SESS_CREATE) == 0 {
			flow := datasplit[11]
			sessionVals.session_time = session_time
			src_dst := strings.Split(flow, "->")
			sessionVals.source_ip = strings.Split(src_dst[0], "/")[0]
			sessionVals.source_port = strings.Split(src_dst[0], "/")[1]
			sessionVals.dest_ip = strings.Split(src_dst[1], "/")[0]
			sessionVals.dest_port = strings.Split(src_dst[1], "/")[1]
			sessTable[flow] = sessionVals
			fmt.Println("added flowinfo to session table\n")
			go programFlow(flow)

		} else if strings.Compare(strings.TrimRight(datasplit[5], " "), SESS_CLOSE) == 0 {
			flow := datasplit[13]
			delete(sessTable, flow)
			fmt.Println("deleted flowinfo from session table\n")
			// TO do: delete flow entries from MX as well
		}
		//fmt.Println(sessTable)
	}
}
