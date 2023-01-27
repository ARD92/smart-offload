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
	"fmt"
	"net"
	"strings"
	"time"
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"gitlab.com/tymonx/go-formatter/formatter"
	jnx "jetoffloader/jnx/jet/common"
	mgmt "jetoffloader/jnx/jet/mgmt"
	auth "jetoffloader/jnx/jet/auth"
)

const (
	HOST = "50.1.1.2" //host to bind app to
	PORT = 514 //port to bind app to
	TYPE = "udp" //protocol type 
	SESS_CREATE = "RT_FLOW_SESSION_CREATE:"
	SESS_CLOSE = "RT_FLOW_SESSION_CLOSE:"
	VALID_SESS_TIME = 3
	JET_HOST = "192.167.1.3"
	JET_PORT = "50051"
	JET_USER = "root"
	JET_PASSWD = "juniper123"
	TIMEOUT = 30
	REDIRECT_IP = "10.1.1.1"
	INDEX = 0
)


// session values which would be stored in maps
type sessionValues struct {
	source_ip string;
	source_port string;
	dest_ip string;
	dest_port string;
	//protocol string;
	session_time string;
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
	loginReq := &auth.LoginRequest {
		Username: JET_USER,
		Password: JET_PASSWD,
		ClientId: clientId,
	}
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	if reply, err := login.Login(junos.cliContext, loginReq); err !=nil {
		fmt.Println("Error authenticating..\n")
	} else if reply.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("Failed to authenticate\n")
	}
	fmt.Println("connected to grpc")
	junos.cliContext = metadata.NewOutgoingContext(context.Background(), md)
	junos.cliClient = mgmt.NewManagementClient(conn)
	return nil
}

// program flow to MX on ephemeral database
func addFlow(name string, src_ip string, dst_ip string, redirect_ip string) {
	var configSlice [] *mgmt.EphemeralConfigSetRequest_ConfigOperation
	xmlTmpl:= `<configuration><routing-options><flow operation='create'><route><name>FLOW_{p}</name><match><source>{p}</source><destination>{p}</destination></match><then><redirect>{p}</redirect></then></route></flow></routing-options></configuration>`
	//xmlTmplAfter:= `<configuration><routing-options><flow><route insert="after" key="[name={p}]" operation="create"><name>{p}</name><match><destination>{p}</destination><source>{p}</source></match><then><redirect>{p}</redirect></then></route></flow></routing-options></configuration>`
	xmlConfig, err := formatter.Format(xmlTmpl, name, src_ip, dst_ip, redirect_ip)
	//fmt.Println(xmlConfig)
	cfgOper := &mgmt.EphemeralConfigSetRequest_ConfigOperation {
		Id: "offload",
		Operation: mgmt.ConfigOperationType_CONFIG_OPERATION_UPDATE,
		Path: "/",
		Value: &mgmt.EphemeralConfigSetRequest_ConfigOperation_XmlConfig {
			XmlConfig: xmlConfig,
		},
	}
	configSlice = append(configSlice, cfgOper)

	output := &mgmt.EphemeralConfigSetRequest {
		InstanceName: "FLOW_OFFLOAD",
		ConfigOperations: configSlice,
		ValidateConfig: false,
		LoadOnly: false,
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
	time.Sleep(30*time.Second)
}

/*
func deFlow() {
	xmlTmpl := `
	    <configuration>
            <routing-options>
                <flow operation="delete"/>
            </routing-options>
    </configuration>
    `
}
*/

// Program valid flows for redirection on MX
// will check if session table still has flow active
func programFlow(flow string) {
	time.Sleep(VALID_SESS_TIME*time.Second)
	// check sesstable if exists 
	val, ok := sessTable[flow]
	if ok {
		fmt.Println("30 seconds elapsed and flow is still active. adding redirection on MX\n")
		fmt.Println(val)
		addFlow(val.source_ip, val.dest_ip, REDIRECT_IP)
	} else {
		fmt.Println("flow doesnt exist. skip programming.. \n")
	}
}

var sessionVals sessionValues
// Map to store {flow1: (sip,dip,sport, dport, protocol, time), flow2:(), flow3:().....}
var sessTable = make(map[string]sessionValues)
// Store the flowspec name
//var flowspecMap = make(map[string]string)

func main() {
	fmt.Println("connected...")
	serverConn,_ := net.ListenUDP("udp", &net.UDPAddr {IP:[]byte{0,0,0,0}, Port:PORT,Zone:""})
	buf := make([]byte, 1024)
	//establish connection to  MX over gRPC channel
	connectJET(JET_HOST+":"+JET_PORT)
	//receive data from udp socket
	for {
		data,_,_ := serverConn.ReadFromUDP(buf)
		bufdata := string(buf[0:data])
		datasplit := strings.SplitAfter(bufdata, " ")
		//sessType := datasplit[5]
		session_time := datasplit[0]+datasplit[1]+datasplit[2]
		if strings.Compare(strings.TrimRight(datasplit[5]," "),SESS_CREATE) == 0 {
			flow := datasplit[11]
			sessionVals.session_time = session_time
			src_dst := strings.Split(flow, "->")
			sessionVals.source_ip = strings.Split(src_dst[0], "/")[0]
			sessionVals.source_port = strings.Split(src_dst[0],"/")[1]
			sessionVals.dest_ip = strings.Split(src_dst[1], "/")[0]
			sessionVals.dest_port = strings.Split(src_dst[1],"/")[1]
			sessTable[flow] =  sessionVals 
			fmt.Println("added flowinfo to session table\n")
			go programFlow(flow)

		} else if strings.Compare(strings.TrimRight(datasplit[5]," "),SESS_CLOSE) == 0 {
			flow := datasplit[13]
			delete(sessTable, flow)
			fmt.Println("deleted flowinfo from session table\n")
			// TO do: delete flow entries from MX as well
		}
		//fmt.Println(sessTable)
	}
}
