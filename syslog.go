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
)

const (
        HOST = "50.1.1.2"
        PORT = "514"
        TYPE = "udp"
        sessCreate = "RT_FLOW_SESSION_CREATE:"
        sessClose = "RT_FLOW_SESSION_CLOSE:"
)

func main() {
        fmt.Println("connected...")
        serverConn,_ := net.ListenUDP("udp", &net.UDPAddr {IP:[]byte{0,0,0,0}, Port:514,Zone:""})
        buf := make([]byte, 1024)
        for {
                data,_,_ := serverConn.ReadFromUDP(buf)
                bufdata := string(buf[0:data])
                datasplit := strings.SplitAfter(bufdata, " ")
                sessType := datasplit[5]
                time := datasplit[0]+datasplit[1]+datasplit[2]
                if strings.Compare(strings.TrimRight(datasplit[5]," "),sessCreate) == 0 {
                        flow := datasplit[11]
                        fmt.Println(time, sessType, flow)
                } else if strings.Compare(strings.TrimRight(datasplit[5]," "),sessClose) == 0 {
                        flow := datasplit[13]
                        fmt.Println(time, sessType, flow)
                }
        }
}
