/*
Author: Aravind Prabhakar
Version: v1.0
Description: Flow offloader on a service chained topology. This app
will listen to syslog session Inits and closes from vSRX and offload the
flow on to MX
*/

package main

import (
	"context"
	"fmt"
	auth "jetoffloader/jnx/jet/auth"
	jnx "jetoffloader/jnx/jet/common"
	fw "jetoffloader/jnx/jet/firewall"
	"net"
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

)

const (
	TYPE            = "udp"         //protocol type
	SESS_CREATE     = "RT_FLOW_SESSION_CREATE"
	SESS_CLOSE      = "RT_FLOW_SESSION_CLOSE"
	VALID_SESS_TIME = 10
	TIMEOUT         = 30
	INDEX           = 0
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
	login := auth.NewAuthenticationClient(conn)
	loginReq := &auth.LoginRequest{
		Username: juser,
		Password: jpass,
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


//generate Hash
func HashString(str string) string {
	h := fnv.New32a()
	h.Write([]byte(str))
	s := strconv.FormatUint(uint64(h.Sum32()),10)
	return s
}

// program default accept term so that it can fall back to cli filter
func programDefaultTerm() {
	cntName := "COUNT-JET-ACCEPT-ALL"
	Action := &fw.FilterTermInetAction {
		ActionsNt: &fw.FilterTermInetNonTerminatingAction {Count: &fw.ActionCounter {CounterName: cntName}}
		ActionT: &fw.FilterTermInetTerminatingAction_ACCEPT
	}
	Adj := &fw.FilterAdjacency { Type: "after", TermName: "(null)" }	
	var filterTermSlice []*fw.FilterTerm
	filterTerm := &fw.FilterInetTerm {
		TermName: "JET-ACCEPT-ALL",
		TermOp: 1 // term add,
		Adjacency: Adj
		Actions: Action
	}
	filterTermSlice = append(filterTermSlice, filterTerm)
	
	// Filter family type : 1 (Ipv4), 2(IPv6)
	// Filter type: 1(Classic), 0 (Invalid)
	output := &fw.FilterAddRequest{
		Name: "FLOW_OFFLOAD",
		Type: 1,
		Family: 1,
		TermsList: filterTermSlice,
	}
	fmt.Println(output)
	resp, err := junos.cliClient.FilterAdd(junos.cliContext, output)
	if err != nil {
		fmt.Println("Failed to program jet-offload default-term")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("failed to program jet-offload default-term")
	} else {
		fmt.Println("successfully programmed jet-offload default-term", resp)
	}
}

// program flow to MX as JET filter
func addFlow(name string, src_ip string, dst_ip string, src_port string, dst_port string) {
	Match := &fw.FilterTermMatchInet {
		//To do: Add protocol if needed
		Ipv4DstAddrs: dst_ip,
		Ipv4SrcAddrs: src_ip,
		DstPorts: dst_port,
		SrcPorts: src_port,
	}
	cntName := "COUNT-"+name
	Action := &fw.FilterTermInetAction {
		ActionsNt: &fw.FilterTermInetNonTerminatingAction {Count: &fw.ActionCounter {CounterName: cntName}}
		ActionT: &fw.FilterTermInetTerminatingAction_ACCEPT
	}
	Adj := &fw.FilterAdjacency { Type: "after", TermName: "JET-ACCEPT-ALL" }	
	var filterTermSlice []*fw.FilterTerm
	filterTerm := &fw.FilterInetTerm {
		TermName: "OFFLOAD_"+name,
		TermOp: 1 // term add,
		Adjacency: Adj
		Matches: Match
		Actions: Action
	}
	filterTermSlice = append(filterTermSlice, filterTerm)
	
	// Filter family type : 1 (Ipv4), 2(IPv6)
	// Filter type: 1(Classic), 0 (Invalid)
	output := &fw.FilterAddRequest{
		Name: "FLOW_OFFLOAD",
		Type: 1,
		Family: 1,
		TermsList: filterTermSlice,
	}
	fmt.Println(output)
	resp, err := junos.cliClient.FilterAdd(junos.cliContext, output)
	if err != nil {
		fmt.Println("Failed to program jet-offload filter")
	} else if resp.Status.Code != jnx.StatusCode_SUCCESS {
		fmt.Println("failed to program jet-offload filter")
	} else {
		fmt.Println("successfully programmed", resp)
	}
}

// delete flow on MX from JET filters
func delFlow(name string) {
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
}

var sessionVals sessionValues

// Map to store {flow1: (sip,dip,sport, dport, protocol, time), flow2:(), flow3:().....}
var sessTable = make(map[string]sessionValues)

// Parse the flow to grab 5 tuple information
func parseFlow(buffer string) (sessionValues, string) {
	datasplit := strings.Split(buffer, " ")
	sessType := strings.TrimRight(datasplit[5], " ")
	if strings.Compare(sessType, SESS_CREATE) == 0 {
		fmt.Println("session create received")
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
		fmt.Println("session close received..")
		fmt.Println(datasplit)
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


// Map to store {flow1: (sip,dip,sport, dport, protocol, time), flow2:(), flow3:().....}
var offloadTable = make(map[string]sessionValues)
//validate flow and offload based on session time threshold

func programFlow(hflow string) {
	time.Sleep(VALID_SESS_TIME * time.Second)
	val, ok := sessTable[hflow]
	if ok {
		fmt.Println("valid session time elapsed and flow is still active. adding redirection on MX\n")
		addFlow(hflow, val.source_ip, val.dest_ip, val.source_port, val.dest_port)
		offloadTable[hflow] = val

	} else {
		fmt.Println("flow doesnt exist. skip programming.. \n")
	}
}

func main() {
	parser := argparse.NewParser("Required-args", "\n============\ntraffic-offloader\n============")
	fmt.Println("connected to host ...")
	port := parser.String("p", "port", &argparse.Options{Required: true, Help: "Port number to bind app to"})
	jip := parser.String("J", "jetip", &argparse.Options{Required: true, Help: "Jet host IP "})
	jport := parser.String("P", "jetport", &argparse.Options{Required: true, Help: "Jet host port"})
	//stime := parser.String("s", "sesstime", &argparse.Options{Required: true, Help: "session time to monitor before programming filters"})
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
		PORT,_ := strconv.Atoi(*port)
		//SESSTIME,_ := strconv.Atoi(*stime) 
		serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: PORT, Zone: ""})
		buf := make([]byte, 1024)
		//establish connection to  MX over gRPC channel
		connectJET(*jip + ":" + *jport, *juser, *jpass)
		//program default accept term to fail over to cli filter for unmatched packets
		programDefaultTerm()
		//receive data from udp socket
		for {
			data, _, _ := serverConn.ReadFromUDP(buf)
			bufdata := string(buf[0:data])
			vals, sessType := parseFlow(bufdata)
			fmt.Println(vals, sessType)
			if strings.Compare(sessType, SESS_CREATE) == 0 {
				flow := vals.source_ip + vals.dest_ip + vals.source_port + vals.dest_port
				hflow := HashString(flow)
				sessTable[hflow] = vals
				go programFlow(hflow)
				fmt.Println("added flowinfo to session table\n")

			} else if strings.Compare(sessType, SESS_CLOSE) == 0 {
				fmt.Println("deleting flow...")
				flow := vals.source_ip + vals.dest_ip + vals.source_port + vals.dest_port
				hflow := HashString(flow)
				delete(sessTable, hflow)
				fmt.Println("Received either session close due to session close msg or due to session time out from vSRX. Deleted flowinfo from session table\n")
			}
		}
	}
}
