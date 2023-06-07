package examples

import (
	"context"

	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	netvuln "github/bountyHntr/netvuln/netvuln.v1"
)

const serverAddress = ":9000"

// example of a client interacting with our gRPC server
// this example corresponds to the execution of the following command:
// nmap -sV -p 53,80 --script vulners scanme.nmap.org
func RequestScanme() {
	var opts []grpc.DialOption
	// for example purposes only, do not use in production
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	conn, err := grpc.Dial(serverAddress, opts...)
	if err != nil {
		log.Fatalf("failed to connect to server at %s: %s", serverAddress, err)
	}
	defer conn.Close()

	cli := netvuln.NewNetVulnServiceClient(conn)

	req := netvuln.CheckVulnRequest{
		Targets:  []string{"scanme.nmap.org"},
		TcpPorts: []int32{53, 80},
	}

	log.Info("send request")
	resp, err := cli.CheckVuln(context.Background(), &req)
	if err != nil {
		log.Fatalf("failed to make request: %s", err)
	}

	log.Println("response:")
	for _, result := range resp.Results {
		log.Println("target:", result.GetTarget())
		for _, service := range result.GetServices() {
			log.Println("\tservice:", service.GetName(), service.GetTcpPort(), service.GetVersion())
			for _, vuln := range service.GetVulns() {
				log.Println("\t\t", vuln.GetIdentifier(), vuln.GetCvssScore())
			}
		}
	}
}
