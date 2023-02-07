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
	"unicode/utf8"
	auth "jetoffloader/jnx/jet/auth"
	jnx "jetoffloader/jnx/jet/common"
	mgmt "jetoffloader/jnx/jet/mgmt"
	"net"
	"strings"
	"time"

	"gitlab.com/tymonx/go-formatter/formatter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	HOST            = "192.171.1.2" //host to bind app to
	PORT            = 514        //port to bind app to
	TYPE            = "udp"      //protocol type
	SESS_CREATE     = "RT_FLOW_SESSION_CREATE"
	SESS_CLOSE      = "RT_FLOW_SESSION_CLOSE"
	VALID_SESS_TIME = 5
	JET_HOST        = "192.167.1.6"
	JET_PORT        = "50051"
	JET_USER        = "root"
	JET_PASSWD      = "juniper123"
	TIMEOUT         = 30
	INDEX = 0
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
	cliClient mgmt.ManagementClient

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
	junos.cliClient = mgmt.NewManagementClient(conn)
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

// program flow to MX on ephemeral database
func addFlow(src_ip string, dst_ip string) {
	var configSlice []*mgmt.EphemeralConfigSetRequest_ConfigOperation
	xmlTmpl := `<configuration><policy-options><prefix-list><name>DEST-PREFIX-OFFLOAD</name><prefix-list-item operation='create'><name>{p}/32</name></prefix-list-item></prefix-list><prefix-list><name>SOURCE-PREFIX-OFFLOAD</name><prefix-list-item operation='create'><name>{p}/32</name></prefix-list-item></prefix-list></policy-options></configuration>`
	xmlConfig, err := formatter.Format(xmlTmpl,dst_ip,src_ip)
	cfgOper := &mgmt.EphemeralConfigSetRequest_ConfigOperation{
		Id:        "offload",
		Operation: mgmt.ConfigOperationType_CONFIG_OPERATION_UPDATE,
		Path:      "/",
		Value: &mgmt.EphemeralConfigSetRequest_ConfigOperation_XmlConfig{
			XmlConfig: xmlConfig,
		},
	}
	configSlice = append(configSlice, cfgOper)

	output := &mgmt.EphemeralConfigSetRequest{
		InstanceName:     "FLOW_OFFLOAD",
		ConfigOperations: configSlice,
		ValidateConfig:   false,
		LoadOnly:         false,
	}
	fmt.Println(output)
	resp, err := junos.cliClient.EphemeralConfigSet(junos.cliContext, output)
	if err != nil {
		fmt.Println("Failed to program config in eDB ")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("failed to program config in eDB")
	} else {
		fmt.Println("successfully programmed", resp)
	}
}

// delete flow on MX on ephemeral DB
func delFlow(src_ip string, dst_ip string) {
	var configSlice []*mgmt.EphemeralConfigSetRequest_ConfigOperation
	xmlTmpl := `<configuration><policy-options><prefix-list><name>DEST-PREFIX-OFFLOAD</name><prefix-list-item operation='delete'><name>{p}</name></prefix-list-item></prefix-list><prefix-list><name>SOURCE-PREFIX-OFFLOAD</name><prefix-list-item operation='delete'><name>{p}</name></prefix-list-item></prefix-list></policy-options></configuration>`
	xmlConfig, err := formatter.Format(xmlTmpl, dst_ip, src_ip)
	cfgOper := &mgmt.EphemeralConfigSetRequest_ConfigOperation{
		Id:        "offload",
		Operation: mgmt.ConfigOperationType_CONFIG_OPERATION_UPDATE,
		Path:      "/",
		Value: &mgmt.EphemeralConfigSetRequest_ConfigOperation_XmlConfig{
			XmlConfig: xmlConfig,
		},
	}
	configSlice = append(configSlice, cfgOper)

	output := &mgmt.EphemeralConfigSetRequest{
		InstanceName:     "FLOW_OFFLOAD",
		ConfigOperations: configSlice,
		ValidateConfig:   false,
		LoadOnly:         false,
	}
	resp, err := junos.cliClient.EphemeralConfigSet(junos.cliContext, output)
	if err != nil {
		fmt.Println("Failed to program config in eDB ")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("failed to program config in eDB")
	} else {
		fmt.Println("successfully deleted the flow", resp)
	}
}


var sessionVals sessionValues

// Map to store {flow1: (sip,dip,sport, dport, protocol, time), flow2:(), flow3:().....}
var sessTable = make(map[string]sessionValues)

// Parse the flow to grab 5 tuple information
func parseFlow(buffer string) (sessionValues, string) {
	datasplit := strings.Split(buffer, " ")
	sessType := strings.TrimRight(datasplit[5]," ")
	if strings.Compare(sessType, SESS_CREATE) == 0 {
		fmt.Println("session create received")
		sessionVals.session_time = datasplit[1]
		for i:=7;i<=10; i++ {
			val := strings.Split(datasplit[i], "=")
			switch val[0] {
			case "source-address":
				sessionVals.source_ip = RemoveFirstChar(RemoveLastChar(val[1]))
			case "source-port":
				sessionVals.source_port = val[1]
			case "destination-address":
				sessionVals.dest_ip = RemoveFirstChar(RemoveLastChar(val[1]))
			case "destination-port":
				sessionVals.dest_port = val[1]
			}
		}
	} else if strings.Compare(sessType, SESS_CLOSE) == 0 {
		fmt.Println("session close received..")
		fmt.Println(datasplit)
		sessionVals.session_time = datasplit[1]
		for i:=7;i<=10; i++ {
			val := strings.Split(datasplit[i], "=")
			switch val[0] {
			case "source-address":
				sessionVals.source_ip = RemoveFirstChar(RemoveLastChar(val[1]))
			case "source-port":
				sessionVals.source_port = val[1]
			case "destination-address":
				sessionVals.dest_ip = RemoveFirstChar(RemoveLastChar(val[1]))
			case "destination-port":
				sessionVals.dest_port = val[1]
			}
		}
	}
	return sessionVals, sessType
}

//validate flow and offload based on session time threshold
func programFlow(flow string){
	time.Sleep(VALID_SESS_TIME * time.Second)
	val, ok := sessTable[flow]
	if ok {
		fmt.Println("30 seconds elapsed and flow is still active. adding redirection on MX\n")
		addFlow(val.source_ip, val.dest_ip)
	} else {
		fmt.Println("flow doesnt exist. skip programming.. \n")
	}
	time.Sleep(VALID_SESS_TIME * time.Second * 2)
	chkAgain, okAgain := sessTable[flow]
	delete(sessTable, flow)
	if okAgain {
		fmt.Println("Flow still active, deleting it..\n")
		delFlow(chkAgain.source_ip, chkAgain.dest_ip)
	}
}


func main() {
	fmt.Println("connected...")
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: PORT, Zone: ""})
	buf := make([]byte, 1024)
	//establish connection to  MX over gRPC channel
	connectJET(JET_HOST + ":" + JET_PORT)
	//receive data from udp socket
	for {
		data, _, _ := serverConn.ReadFromUDP(buf)
		bufdata := string(buf[0:data])
		vals, sessType := parseFlow(bufdata)
		fmt.Println(vals, sessType)
		if strings.Compare(sessType, SESS_CREATE) == 0 {
			flow := vals.source_ip +"->"+vals.dest_ip
			sessTable[flow] = vals
			go programFlow(flow)
			fmt.Println("added flowinfo to session table\n")

		} else if strings.Compare(sessType, SESS_CLOSE) == 0 {
			fmt.Println("deleting flow...")
			flow := vals.source_ip+"->"+vals.dest_ip
			delete(sessTable, flow)
			fmt.Println("deleted flowinfo from session table\n")
			// TO do: delete flow entries from MX as well
			go delFlow(vals.source_ip, vals.dest_ip)
		}
		//fmt.Println(sessTable)
	}
}
