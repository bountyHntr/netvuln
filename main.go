package main

import (
	netvuln "github/bountyHntr/netvuln/netvuln.v1"
	"net"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"google.golang.org/grpc"
)

var serverAddress = ":9000" // default server address

// environment variables parsing
func init() {
	logLevelStr, ok := os.LookupEnv("LOG_LVL")
	if ok {
		logLevel, err := log.ParseLevel(logLevelStr)
		if err == nil {
			log.SetLevel(logLevel)
		} else {
			log.Warnf("invalid LOG_LEVEL environment varibale value: %s; default `INFO` level is used", logLevelStr)
		}
	}

	if srvAddr, ok := os.LookupEnv("SRV_ADDR"); ok {
		serverAddress = srvAddr
	}
}

func main() {
	listener, err := net.Listen("tcp", serverAddress)
	if err != nil {
		log.Fatalf("failed to run listener at '%s': %s", serverAddress, err)
	}

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	nv, err := netvuln.NewNetVulnServer()
	if err != nil {
		log.Fatalf("failed to init new server: %s", err)
	}
	netvuln.RegisterNetVulnServiceServer(grpcServer, nv)

	catchStopSignal(grpcServer)

	log.Infof("run gRPC server at %s", serverAddress)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("server is broken: %s", err)
	}
}

func catchStopSignal(srv *grpc.Server) {
	stopChan := make(chan os.Signal, 10)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopChan
		srv.GracefulStop()
	}()
}
