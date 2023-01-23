/*
Author: Aravind Prabhakar
Version: v1.0
Description: Flow offloader
*/

package main

import (
	"fmt"
	"net"
	"strings"
	"time"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	HOST = "50.1.1.2" //host to bind app to
	PORT = 514 //port to bind app to
	TYPE = "udp" //protocol type 
	SESS_CREATE = "RT_FLOW_SESSION_CREATE:"
	SESS_CLOSE = "RT_FLOW_SESSION_CLOSE:"
	VALID_SESS_TIME = 30
	JET_HOST = "192.167.1.3"
	JET_PORT = 50051
	JET_PASSWD = "juniper123"
)


// session values which would be stored in maps
type sessionValues struct {
	//source_ip string;
	//source_port string;
	//dest_ip string;
	//dest_port string;
	//protocol string;
	session_time string;
}

// Program valid flows for redirection on MX
// will check if session table still has flow active
func programFlow(flow string) {
	time.Sleep(VALID_SESS_TIME*time.Second)
	// check sesstable if exists 
	val, ok := sessTable[flow]
	if ok {
		fmt.Println("30 seconds elapsed and flow is still active. adding redirection on MX\n")
		fmt.Println(val, flow)
	} else {
		fmt.Println("flow doesnt exist. skip programming.. \n")
	}
}

/*
func connectJET(){
	var conn *grpc.ClientConn
	conn, err := grpc.Dial(JET_HOST+":"+JET_PORT, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.close()
	clientID := "traffic-offload"

func addFlow(flow){
}

func delFlow(){
}*/


var sessionVals sessionValues
// Map to store {flow1: (sip,dip,sport, dport, protocol, time), flow2:(), flow3:().....}
var sessTable = make(map[string]sessionValues)

func main() {
	fmt.Println("connected...")
	serverConn,_ := net.ListenUDP("udp", &net.UDPAddr {IP:[]byte{0,0,0,0}, Port:PORT,Zone:""})
	buf := make([]byte, 1024)
	
	for {
		data,_,_ := serverConn.ReadFromUDP(buf)
		bufdata := string(buf[0:data])
		datasplit := strings.SplitAfter(bufdata, " ")
		//sessType := datasplit[5]
		session_time := datasplit[0]+datasplit[1]+datasplit[2]
		if strings.Compare(strings.TrimRight(datasplit[5]," "),SESS_CREATE) == 0 {
			flow := datasplit[11]
			sessionVals.session_time = session_time
			sessTable[flow] =  sessionVals 
			fmt.Println("added flowinfo to session table\n")
			go programFlow(flow)

		} else if strings.Compare(strings.TrimRight(datasplit[5]," "),SESS_CLOSE) == 0 {
			flow := datasplit[13]
			delete(sessTable, flow)
			fmt.Println("deleted flowinfo from session table\n")
			// delete flow entries from MX as well
		}
	}
}
