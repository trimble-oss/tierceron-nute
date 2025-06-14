package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net"
	"strconv"

	"github.com/trimble-oss/tierceron-nute-core/mashupsdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server bootstrapping is concerned with establishing connection with
// mashup, handshaking, and establishing credential sets.  It
// also sets up signal handling in event of either system
// shutting down.

var clientConnectionConfigs *mashupsdk.MashupConnectionConfigs
var serverConnectionConfigs *mashupsdk.MashupConnectionConfigs

var maxMessage int
var initHandler mashupsdk.MashupContextInitHandler
var security bool

// RemoteInitServer -- Bootstraps the initialization of the remote server with the location specified in creds paramater
func RemoteInitServer(creds string, insecure bool, maxMessageLength int, mashupApiHandler mashupsdk.MashupApiHandler, mashupContextInitHandler mashupsdk.MashupContextInitHandler) {
	serverConfigs := &mashupsdk.MashupConnectionConfigs{}
	maxMessage = maxMessageLength
	initHandler = mashupContextInitHandler
	security = insecure
	err := json.Unmarshal([]byte(creds), serverConfigs)
	if err != nil {
		log.Printf("Malformed credentials: %s %v", creds, err)
		return
	}
	log.Printf("Startup with insecure: %t\n", insecure)

	go func(mapiH mashupsdk.MashupApiHandler) {
		cert, err := tls.X509KeyPair(mashupsdk.MashupCertBytes, mashupsdk.MashupKeyBytes)
		if err != nil {
			log.Printf("Couldn't construct key pair: %v", err)
			return
		}
		creds := credentials.NewServerTLSFromCert(&cert)

		var remote_server *grpc.Server
		if maxMessageLength > 0 {
			remote_server = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
		} else {
			remote_server = grpc.NewServer(grpc.Creds(creds))
		}

		lis, err := net.Listen("tcp", serverConfigs.Server+":"+strconv.Itoa(int(serverConfigs.Port)))
		if err != nil {
			log.Printf("failed to serve: %v", err)
			return
		}

		// Initialize the mashup server configuration and auth
		// token.
		serverConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
			AuthToken:   serverConfigs.AuthToken, // server token.
			CallerToken: serverConfigs.AuthToken,
			Server:      serverConfigs.Server,
			Port:        serverConfigs.Port,
		}

		go func(mH mashupsdk.MashupApiHandler) {
			// Async service initiation.
			log.Printf("Start Registering server.\n")

			mashupsdk.RegisterMashupServerServer(remote_server, &MashupServer{mashupApiHandler: mH})

			log.Printf("My Starting service.\n")
			if err := remote_server.Serve(lis); err != nil {
				log.Printf("failed to serve: %v", err)
				return
			}
		}(mapiH)
		log.Printf("Handshake initiated.\n")
	}(mashupApiHandler)
}

// InitServer -- bootstraps the server portion of the sdk for the mashup.
func InitServer(creds string, insecure bool, maxMessageLength int, mashupApiHandler mashupsdk.MashupApiHandler, mashupContextInitHandler mashupsdk.MashupContextInitHandler) {
	// Perform handshake...
	handshakeConfigs := &mashupsdk.MashupConnectionConfigs{}

	err := json.Unmarshal([]byte(creds), handshakeConfigs)
	if err != nil {
		log.Fatalf("Malformed credentials: %s %v", creds, err)
	}
	log.Printf("Startup with insecure: %t\n", insecure)

	go func(mapiH mashupsdk.MashupApiHandler) {
		cert, err := tls.X509KeyPair(mashupsdk.MashupCertBytes, mashupsdk.MashupKeyBytes)
		if err != nil {
			log.Fatalf("Couldn't construct key pair: %v", err)
		}
		creds := credentials.NewServerTLSFromCert(&cert)

		var s *grpc.Server

		if maxMessageLength > 0 {
			s = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
		} else {
			s = grpc.NewServer(grpc.Creds(creds))
		}

		lis, err := net.Listen("tcp", handshakeConfigs.Server+":0")
		if err != nil {
			log.Fatalf("failed to serve: %v", err)
		}

		// Initialize the mashup server configuration and auth
		// token.
		serverConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
			AuthToken: mashupsdk.GenAuthToken(), // server token.
			Server:    handshakeConfigs.Server,
			Port:      int64(lis.Addr().(*net.TCPAddr).Port),
		}

		// Connect to the server for purposes of mashup api calls.
		mashupCertPool := x509.NewCertPool()
		mashupBlock, _ := pem.Decode([]byte(mashupsdk.MashupCertBytes))
		mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
		if err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
		mashupCertPool.AddCert(mashupClientCert)

		var defaultDialOpt grpc.DialOption = grpc.EmptyDialOption{}

		if maxMessageLength > 0 {
			defaultDialOpt = grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageLength), grpc.MaxCallSendMsgSize(maxMessageLength))
		}
		// Send credentials back to client....
		conn, err := grpc.Dial(handshakeConfigs.Server+":"+strconv.Itoa(int(handshakeConfigs.Port)), defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: insecure})))
		if err != nil {
			log.Fatalf("did not connect: %v", err)
		}
		mashupContext := &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: nil}

		// Contact the server and print out its response.
		// User's of this library will benefit in following way:
		// 1. If current application shuts down, mashup
		// will also be told to shut down through Shutdown() api
		// call before this app exits.
		mashupContext.Client = mashupsdk.NewMashupServerClient(conn)

		if mashupContextInitHandler != nil {
			mashupContextInitHandler.RegisterContext(mashupContext)
		}

		go func(mH mashupsdk.MashupApiHandler) {
			// Async service initiation.
			log.Printf("Start Registering server.\n")

			mashupsdk.RegisterMashupServerServer(s, &MashupServer{mashupApiHandler: mH})

			log.Printf("My Starting service.\n")
			if err := s.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}(mapiH)

		log.Printf("Handshake initiated.\n")

		callerToken := handshakeConfigs.CallerToken
		handshakeConfigs.AuthToken = callerToken
		handshakeConfigs.CallerToken = serverConnectionConfigs.AuthToken
		handshakeConfigs.Server = serverConnectionConfigs.Server
		handshakeConfigs.Port = serverConnectionConfigs.Port

		clientConnectionConfigs, err = mashupContext.Client.CollaborateInit(mashupContext.Context, handshakeConfigs)
		if err != nil {
			log.Printf("handshake failure: %v\n", err)
			panic(err)
		}
		log.Printf("Handshake complete.\n")

	}(mashupApiHandler)
}
