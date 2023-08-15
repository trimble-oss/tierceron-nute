package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net"
	"os"
	"sync"

	"github.com/trimble-oss/tierceron-nute/mashupsdk"
	sdk "github.com/trimble-oss/tierceron-nute/mashupsdk"
	"github.com/trimble-oss/tierceron-nute/mashupsdk/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server bootstrapping is concerned with establishing connection with
// mashup, handshaking, and establishing credential sets.  It
// also sets up signal handling in event of either system
// shutting down.

var clientConnectionConfigs *sdk.MashupConnectionConfigs
var serverConnectionConfigs *sdk.MashupConnectionConfigs

func InitServer(creds string, insecure bool, maxMessageLength int, mashupApiHandler mashupsdk.MashupApiHandler, mashupContextInitHandler mashupsdk.MashupContextInitHandler) {
	// mashupCertBytes, err := mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
	// if err != nil {
	// 	log.Printf("Couldn't load cert: %v", err)
	// 	return
	// }

	// mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
	// if err != nil {
	// 	log.Fatalf("Couldn't load key: %v", err)
	// }

	// cert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
	// if err != nil {
	// 	log.Fatalf("Couldn't construct key pair: %v", err)
	// }
	// cred := credentials.NewServerTLSFromCert(&cert)
	// s := grpc.NewServer(grpc.Creds(cred))

	// // flumeworld := FlumeWorldApp{}

	// port := os.Getenv("PORT")
	// if port == "" {
	// 	port = "8080"
	// }
	// lis, err := net.Listen("tcp", ":"+port)
	// if err != nil {
	// 	log.Fatalf("failed to listen: %v", err)
	// }

	// serverConnectionConfigs := &mashupsdk.MashupConnectionConfigs{
	// 	AuthToken: "c5376ccf9edc2a02499716c7e4f5599e8a96747e8a762c8ebed7a45074ad192a", // server token.
	// 	Port:      int64(lis.Addr().(*net.TCPAddr).Port),
	// }
	// log.Println(serverConnectionConfigs)
	// client.SetServerConfigs(serverConnectionConfigs)
	// SetServerConfigs(serverConnectionConfigs)
	// mashupCertPool := x509.NewCertPool()
	// mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
	// mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
	// if err != nil {
	// 	log.Fatalf("failed to serve: %v", err)
	// }
	// mashupCertPool.AddCert(mashupClientCert)

	// defaultDialOpt := grpc.EmptyDialOption{}
	// conn, err := grpc.Dial("localhost:"+port, defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: true})))
	// if err != nil {
	// 	log.Fatalf("did not connect: %v", err)
	// }
	// mashupContext := &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: nil}
	// mashupContext.Client = mashupsdk.NewMashupServerClient(conn)

	// log.Printf("Start Registering server.\n")
	// serv := &MashupServer{}
	// // serv.SetHandler(flumeworld.MashupSdkApiHandler)
	// mashupsdk.RegisterMashupServerServer(s, serv)
	// log.Printf("server listening at %v", lis.Addr())
	// log.Printf("My Starting service.\n")
	// if err := s.Serve(lis); err != nil {
	// 	log.Fatalf("failed to serve: %v", err)
	// }

	// Perform handshake...
	handshakeConfigs := &mashupsdk.MashupConnectionConfigs{}
	err := json.Unmarshal([]byte(creds), handshakeConfigs)
	if err != nil {
		log.Printf("Malformed credentials: %s %v", creds, err)
		return
	}
	log.Printf("Startup with insecure: %t\n", insecure)
	var wg sync.WaitGroup
	wg.Add(1)
	go func(mapiH mashupsdk.MashupApiHandler) {
		mashupCertBytes, err := mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
		if err != nil {
			log.Printf("Couldn't load cert: %v", err)
			return
		}

		mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
		if err != nil {
			log.Printf("Couldn't load key: %v", err)
			return
		}

		cert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
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

		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		lis, err := net.Listen("tcp", ":"+port)
		if err != nil {
			log.Printf("failed to listen: %v", err)
			return
		}

		// lis, err := net.Listen("tcp", "localhost:0")
		// if err != nil {
		// 	log.Fatalf("failed to serve: %v", err)
		// }

		// Initialize the mashup server configuration and auth
		// token.
		if maxMessageLength == -2 {
			serverConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
				AuthToken: "c5376ccf9edc2a02499716c7e4f5599e8a96747e8a762c8ebed7a45074ad192a", // server token.
				Port:      int64(lis.Addr().(*net.TCPAddr).Port),
			}
		} else {
			serverConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
				AuthToken: mashupsdk.GenAuthToken(), // server token.
				Port:      int64(lis.Addr().(*net.TCPAddr).Port),
			}
		}

		client.SetServerConfigs(serverConnectionConfigs)

		// Connect to the server for purposes of mashup api calls.
		mashupCertPool := x509.NewCertPool()
		mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
		mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
		if err != nil {
			log.Printf("failed to serve: %v", err)
			return
		}
		mashupCertPool.AddCert(mashupClientCert)

		var defaultDialOpt grpc.DialOption = grpc.EmptyDialOption{}

		if maxMessageLength > 0 {
			defaultDialOpt = grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageLength), grpc.MaxCallSendMsgSize(maxMessageLength))
		}
		// Send credentials back to client....
		conn, err := grpc.Dial("localhost:"+port, defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: insecure}))) //strconv.Itoa(int(handshakeConfigs.Port))
		if err != nil {
			log.Printf("did not connect: %v", err)
			return
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
			serv := &MashupServer{mashupApiHandler: mH}
			mashupsdk.RegisterMashupServerServer(s, serv)

			log.Printf("My Starting service.\n")
			if err := s.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}(mapiH)

		log.Printf("Handshake initiated.\n")
		if maxMessageLength != -2 {
			localInitServer(mashupContext, *handshakeConfigs)
		}
		log.Printf("Handshake complete.\n")

	}(mashupApiHandler)
	wg.Wait()
}

func localInitServer(mashupContext *mashupsdk.MashupContext, handshakeConfigs mashupsdk.MashupConnectionConfigs) {
	callerToken := handshakeConfigs.CallerToken
	handshakeConfigs.AuthToken = callerToken
	handshakeConfigs.CallerToken = serverConnectionConfigs.AuthToken
	handshakeConfigs.Port = serverConnectionConfigs.Port
	var err error
	clientConnectionConfigs, err = mashupContext.Client.CollaborateInit(mashupContext.Context, &handshakeConfigs)
	if err != nil {
		log.Printf("handshake failure: %v\n", err)
		panic(err)
	}
}

// InitServer -- bootstraps the server portion of the sdk for the mashup.
// func InitServer(creds string, insecure bool, maxMessageLength int, mashupApiHandler mashupsdk.MashupApiHandler, mashupContextInitHandler mashupsdk.MashupContextInitHandler) {
// 	// Perform handshake...
// 	handshakeConfigs := &sdk.MashupConnectionConfigs{}
// 	err := json.Unmarshal([]byte(creds), handshakeConfigs)
// 	if err != nil {
// 		log.Fatalf("Malformed credentials: %s %v", creds, err)
// 	}
// 	log.Printf("Startup with insecure: %t\n", insecure)

// 	go func(mapiH mashupsdk.MashupApiHandler) {
// 		mashupCertBytes, err := sdk.MashupCert.ReadFile("tls/mashup.crt")
// 		if err != nil {
// 			log.Fatalf("Couldn't load cert: %v", err)
// 		}

// 		mashupKeyBytes, err := sdk.MashupKey.ReadFile("tls/mashup.key")
// 		if err != nil {
// 			log.Fatalf("Couldn't load key: %v", err)
// 		}

// 		cert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
// 		if err != nil {
// 			log.Fatalf("Couldn't construct key pair: %v", err)
// 		}
// 		creds := credentials.NewServerTLSFromCert(&cert)

// 		var s *grpc.Server

// 		if maxMessageLength > 0 {
// 			s = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
// 		} else {
// 			s = grpc.NewServer(grpc.Creds(creds))
// 		}

// 		lis, err := net.Listen("tcp", "localhost:0")
// 		if err != nil {
// 			log.Fatalf("failed to serve: %v", err)
// 		}

// 		// Initialize the mashup server configuration and auth
// 		// token.
// 		serverConnectionConfigs = &sdk.MashupConnectionConfigs{
// 			AuthToken: sdk.GenAuthToken(), // server token.
// 			Port:      int64(lis.Addr().(*net.TCPAddr).Port),
// 		}

// 		// Connect to the server for purposes of mashup api calls.
// 		mashupCertPool := x509.NewCertPool()
// 		mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
// 		mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
// 		if err != nil {
// 			log.Fatalf("failed to serve: %v", err)
// 		}
// 		mashupCertPool.AddCert(mashupClientCert)

// 		var defaultDialOpt grpc.DialOption = grpc.EmptyDialOption{}

// 		if maxMessageLength > 0 {
// 			defaultDialOpt = grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageLength), grpc.MaxCallSendMsgSize(maxMessageLength))
// 		}
// 		// Send credentials back to client....
// 		conn, err := grpc.Dial("localhost:"+strconv.Itoa(int(handshakeConfigs.Port)), defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: insecure})))
// 		if err != nil {
// 			log.Fatalf("did not connect: %v", err)
// 		}
// 		mashupContext := &sdk.MashupContext{Context: context.Background(), MashupGoodies: nil}

// 		// Contact the server and print out its response.
// 		// User's of this library will benefit in following way:
// 		// 1. If current application shuts down, mashup
// 		// will also be told to shut down through Shutdown() api
// 		// call before this app exits.
// 		mashupContext.Client = sdk.NewMashupServerClient(conn)

// 		if mashupContextInitHandler != nil {
// 			mashupContextInitHandler.RegisterContext(mashupContext)
// 		}

// 		go func(mH mashupsdk.MashupApiHandler) {
// 			// Async service initiation.
// 			log.Printf("Start Registering server.\n")

// 			sdk.RegisterMashupServerServer(s, &MashupServer{mashupApiHandler: mH})

// 			log.Printf("My Starting service.\n")
// 			if err := s.Serve(lis); err != nil {
// 				log.Fatalf("failed to serve: %v", err)
// 			}
// 		}(mapiH)

// 		log.Printf("Handshake initiated.\n")

// 		callerToken := handshakeConfigs.CallerToken
// 		handshakeConfigs.AuthToken = callerToken
// 		handshakeConfigs.CallerToken = serverConnectionConfigs.AuthToken
// 		handshakeConfigs.Port = serverConnectionConfigs.Port

// 		clientConnectionConfigs, err = mashupContext.Client.CollaborateInit(mashupContext.Context, handshakeConfigs)
// 		if err != nil {
// 			log.Printf("handshake failure: %v\n", err)
// 			panic(err)
// 		}
// 		log.Printf("Handshake complete.\n")

// 	}(mashupApiHandler)
// }
