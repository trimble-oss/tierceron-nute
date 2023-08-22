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

	"github.com/trimble-oss/tierceron-nute/mashupsdk"
	// sdk "github.com/trimble-oss/tierceron-nute/mashupsdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server bootstrapping is concerned with establishing connection with
// mashup, handshaking, and establishing credential sets.  It
// also sets up signal handling in event of either system
// shutting down.

var clientConnectionConfigs *mashupsdk.MashupConnectionConfigs
var serverConnectionConfigs *mashupsdk.MashupConnectionConfigs
var handshakeConnectionConfigs *mashupsdk.MashupConnectionConfigs

func RemoteInitServer(server_name string, creds string, insecure bool, maxMessageLength int, mashupApiHandler mashupsdk.MashupApiHandler, mashupContextInitHandler mashupsdk.MashupContextInitHandler) {
	//To Do:
	// Set up credentials:
	handshakeConfigs := &mashupsdk.MashupConnectionConfigs{}

	err := json.Unmarshal([]byte(creds), handshakeConfigs)
	if err != nil {
		log.Fatalf("Malformed credentials: %s %v", creds, err)
	}
	log.Printf("Startup with insecure: %t\n", insecure)

	go func(mapiH mashupsdk.MashupApiHandler) {
		mashupCertBytes, err := mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
		if err != nil {
			log.Fatalf("Couldn't load cert: %v", err)
		}

		mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
		if err != nil {
			log.Fatalf("Couldn't load key: %v", err)
		}

		cert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
		if err != nil {
			log.Fatalf("Couldn't construct key pair: %v", err)
		}
		creds := credentials.NewServerTLSFromCert(&cert)
		// 1. Set up Remote server
		var remote_server *grpc.Server

		if maxMessageLength > 0 {
			remote_server = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
		} else {
			remote_server = grpc.NewServer(grpc.Creds(creds))
		}

		lis, err := net.Listen("tcp", server_name+":0") //This could be localhost still?
		if err != nil {
			log.Fatalf("failed to serve: %v", err)
		}

		// Initialize the mashup server configuration and auth
		// token.
		serverConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
			AuthToken: mashupsdk.GenAuthToken(), // server token.
			Server:    server_name,
			Port:      int64(lis.Addr().(*net.TCPAddr).Port),
		}

		// 2. Set up Handshake Server
		var handshake_server *grpc.Server

		if maxMessageLength > 0 {
			handshake_server = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
		} else {
			handshake_server = grpc.NewServer(grpc.Creds(creds))
		}

		handshake_lis, err := net.Listen("tcp", handshakeConfigs.Server+":0") //This could be localhost still?
		if err != nil {
			log.Fatalf("failed to serve: %v", err)
		}

		// Initialize the mashup server configuration and auth
		// token.
		handshakeConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
			AuthToken: mashupsdk.GenAuthToken(), // handshake token.
			Server:    handshakeConfigs.Server,
			Port:      int64(handshake_lis.Addr().(*net.TCPAddr).Port),
		}
		log.Printf("Handshake Server listening on port: %v", handshakeConnectionConfigs.Port)

		mashupCertPool := x509.NewCertPool()
		mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
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
		remote_conn, err := grpc.Dial(server_name+":"+strconv.Itoa(int(serverConnectionConfigs.Port)), defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: insecure})))
		if err != nil {
			log.Fatalf("did not connect: %v", err)
		}

		handshake_conn, err := grpc.Dial(handshakeConnectionConfigs.Server+":"+strconv.Itoa(int(handshakeConnectionConfigs.Port)), defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: insecure})))
		if err != nil {
			log.Fatalf("did not connect: %v", err)
		}

		//Potentially give serverconnectionconfigs inside MashupGoodies for handshakeContext???

		handshakeContext := &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: nil}
		handshakeContext.Client = mashupsdk.NewMashupServerClient(handshake_conn)

		mashupContext := &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: nil}
		mashupContext.Client = mashupsdk.NewMashupServerClient(remote_conn)

		if mashupContextInitHandler != nil {
			mashupContextInitHandler.RegisterContext(mashupContext)
		}

		go func(mH mashupsdk.MashupApiHandler) {
			// Async service initiation.
			log.Printf("Start Registering server.\n")

			mashupsdk.RegisterMashupServerServer(remote_server, &MashupServer{mashupApiHandler: mH})

			log.Printf("My Starting service.\n")
			if err := remote_server.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}(mapiH)

		go func(mH mashupsdk.MashupApiHandler) {
			// Async service initiation.
			log.Printf("Start Registering handshake server.\n")

			mashupsdk.RegisterMashupServerServer(handshake_server, &MashupServer{mashupApiHandler: mH})

			log.Printf("My Starting handshake service.\n")
			if err := handshake_server.Serve(handshake_lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}(mapiH)

		log.Printf("Handshake initiated.\n")

	}(mashupApiHandler)

	// 3. Attach Handshake Server as a client of remote server
	// 4. Listen on Remote server and handshake server endpoints

	// Perform handshake...
	// handshakeConfigs := &mashupsdk.MashupConnectionConfigs{}

	// err := json.Unmarshal([]byte(creds), handshakeConfigs)
	// if err != nil {
	// 	log.Fatalf("Malformed credentials: %s %v", creds, err)
	// }
	// log.Printf("Startup with insecure: %t\n", insecure)

	// go func(mapiH mashupsdk.MashupApiHandler) {
	// 	mashupCertBytes, err := mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
	// 	if err != nil {
	// 		log.Fatalf("Couldn't load cert: %v", err)
	// 	}

	// 	mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
	// 	if err != nil {
	// 		log.Fatalf("Couldn't load key: %v", err)
	// 	}

	// 	cert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
	// 	if err != nil {
	// 		log.Fatalf("Couldn't construct key pair: %v", err)
	// 	}
	// 	creds := credentials.NewServerTLSFromCert(&cert)

	// 	var s *grpc.Server

	// 	if maxMessageLength > 0 {
	// 		s = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
	// 	} else {
	// 		s = grpc.NewServer(grpc.Creds(creds))
	// 	}

	// 	lis, err := net.Listen("tcp", handshakeConfigs.Server+":0") //This could be localhost still?
	// 	if err != nil {
	// 		log.Fatalf("failed to serve: %v", err)
	// 	}

	// 	// Initialize the mashup server configuration and auth
	// 	// token.
	// 	serverConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
	// 		AuthToken: mashupsdk.GenAuthToken(), // server token.
	// 		Server:    handshakeConfigs.Server,
	// 		Port:      int64(lis.Addr().(*net.TCPAddr).Port),
	// 	}

	// 	// Connect to the server for purposes of mashup api calls.
	// 	mashupCertPool := x509.NewCertPool()
	// 	mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
	// 	mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
	// 	if err != nil {
	// 		log.Fatalf("failed to serve: %v", err)
	// 	}
	// 	mashupCertPool.AddCert(mashupClientCert)

	// 	var defaultDialOpt grpc.DialOption = grpc.EmptyDialOption{}

	// 	if maxMessageLength > 0 {
	// 		defaultDialOpt = grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageLength), grpc.MaxCallSendMsgSize(maxMessageLength))
	// 	}
	// 	// Send credentials back to client....
	// 	conn, err := grpc.Dial(handshakeConfigs.Server+":"+strconv.Itoa(int(handshakeConfigs.Port)), defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: insecure})))
	// 	if err != nil {
	// 		log.Fatalf("did not connect: %v", err)
	// 	}
	// 	mashupContext := &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: nil}

	// 	// Contact the server and print out its response.
	// 	// User's of this library will benefit in following way:
	// 	// 1. If current application shuts down, mashup
	// 	// will also be told to shut down through Shutdown() api
	// 	// call before this app exits.
	// 	mashupContext.Client = mashupsdk.NewMashupServerClient(conn)

	// 	if mashupContextInitHandler != nil {
	// 		mashupContextInitHandler.RegisterContext(mashupContext)
	// 	}

	// 	go func(mH mashupsdk.MashupApiHandler) {
	// 		// Async service initiation.
	// 		log.Printf("Start Registering server.\n")

	// 		mashupsdk.RegisterMashupServerServer(s, &MashupServer{mashupApiHandler: mH})

	// 		log.Printf("My Starting service.\n")
	// 		if err := s.Serve(lis); err != nil {
	// 			log.Fatalf("failed to serve: %v", err)
	// 		}
	// 	}(mapiH)

	// 	log.Printf("Handshake initiated.\n")

	// 	callerToken := handshakeConfigs.CallerToken
	// 	handshakeConfigs.AuthToken = callerToken
	// 	handshakeConfigs.CallerToken = serverConnectionConfigs.AuthToken
	// 	handshakeConfigs.Server = serverConnectionConfigs.Server
	// 	handshakeConfigs.Port = serverConnectionConfigs.Port

	// 	clientConnectionConfigs, err = mashupContext.Client.CollaborateInit(mashupContext.Context, handshakeConfigs)
	// 	if err != nil {
	// 		log.Printf("handshake failure: %v\n", err)
	// 		panic(err)
	// 	}
	// 	log.Printf("Handshake complete.\n")

	// }(mashupApiHandler)
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
		mashupCertBytes, err := mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
		if err != nil {
			log.Fatalf("Couldn't load cert: %v", err)
		}

		mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
		if err != nil {
			log.Fatalf("Couldn't load key: %v", err)
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

		lis, err := net.Listen("tcp", handshakeConfigs.Server+":0") //This could be localhost still?
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
		mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
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

// package server

// import (
// 	"context"
// 	"crypto/tls"
// 	"crypto/x509"
// 	"encoding/json"
// 	"encoding/pem"
// 	"log"
// 	"net"
// 	"os"
// 	"sync"

// 	"github.com/trimble-oss/tierceron-nute/mashupsdk"
// 	"github.com/trimble-oss/tierceron-nute/mashupsdk/client"

// 	// "github.com/trimble-oss/tierceron-nute/mashupsdk/client"
// 	"google.golang.org/grpc"
// 	"google.golang.org/grpc/credentials"
// )

// // Server bootstrapping is concerned with establishing connection with
// // mashup, handshaking, and establishing credential sets.  It
// // also sets up signal handling in event of either system
// // shutting down.

// var clientConnectionConfigs *mashupsdk.MashupConnectionConfigs
// var serverConnectionConfigs *mashupsdk.MashupConnectionConfigs

// var curr_server *MashupServer
// var apihandler mashupsdk.MashupApiHandler

// func InitServer(creds string, insecure bool, maxMessageLength int, mashupApiHandler mashupsdk.MashupApiHandler, mashupContextInitHandler mashupsdk.MashupContextInitHandler) {
// 	// mashupCertBytes, err := mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
// 	// if err != nil {
// 	// 	log.Printf("Couldn't load cert: %v", err)
// 	// 	return
// 	// }

// 	// mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
// 	// if err != nil {
// 	// 	log.Fatalf("Couldn't load key: %v", err)
// 	// }

// 	// cert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
// 	// if err != nil {
// 	// 	log.Fatalf("Couldn't construct key pair: %v", err)
// 	// }
// 	// cred := credentials.NewServerTLSFromCert(&cert)
// 	// s := grpc.NewServer(grpc.Creds(cred))

// 	// // flumeworld := FlumeWorldApp{}

// 	// port := os.Getenv("PORT")
// 	// if port == "" {
// 	// 	port = "8080"
// 	// }
// 	// lis, err := net.Listen("tcp", ":"+port)
// 	// if err != nil {
// 	// 	log.Fatalf("failed to listen: %v", err)
// 	// }

// 	// serverConnectionConfigs := &mashupsdk.MashupConnectionConfigs{
// 	// 	AuthToken: "", // server token.
// 	// 	Port:      int64(lis.Addr().(*net.TCPAddr).Port),
// 	// }
// 	// log.Println(serverConnectionConfigs)
// 	// client.SetServerConfigs(serverConnectionConfigs)
// 	// SetServerConfigs(serverConnectionConfigs)
// 	// mashupCertPool := x509.NewCertPool()
// 	// mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
// 	// mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
// 	// if err != nil {
// 	// 	log.Fatalf("failed to serve: %v", err)
// 	// }
// 	// mashupCertPool.AddCert(mashupClientCert)

// 	// defaultDialOpt := grpc.EmptyDialOption{}
// 	// conn, err := grpc.Dial("localhost:"+port, defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: true})))
// 	// if err != nil {
// 	// 	log.Fatalf("did not connect: %v", err)
// 	// }
// 	// mashupContext := &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: nil}
// 	// mashupContext.Client = mashupsdk.NewMashupServerClient(conn)

// 	// log.Printf("Start Registering server.\n")
// 	// serv := &MashupServer{}
// 	// // serv.SetHandler(flumeworld.MashupSdkApiHandler)
// 	// mashupsdk.RegisterMashupServerServer(s, serv)
// 	// log.Printf("server listening at %v", lis.Addr())
// 	// log.Printf("My Starting service.\n")
// 	// if err := s.Serve(lis); err != nil {
// 	// 	log.Fatalf("failed to serve: %v", err)
// 	// }

// 	// Perform handshake...
// 	handshakeConfigs := &mashupsdk.MashupConnectionConfigs{}
// 	err := json.Unmarshal([]byte(creds), handshakeConfigs)
// 	if err != nil {
// 		log.Printf("Malformed credentials: %s %v", creds, err)
// 		return
// 	}
// 	log.Printf("Startup with insecure: %t\n", insecure)
// 	var wg sync.WaitGroup
// 	wg.Add(1)
// 	go func(mapiH mashupsdk.MashupApiHandler) {
// 		mashupCertBytes, err := mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
// 		if err != nil {
// 			log.Printf("Couldn't load cert: %v", err)
// 			return
// 		}

// 		mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
// 		if err != nil {
// 			log.Printf("Couldn't load key: %v", err)
// 			return
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

// 		port := os.Getenv("PORT")
// 		if port == "" {
// 			port = "8080"
// 		}
// 		lis, err := net.Listen("tcp", ":"+port)
// 		if err != nil {
// 			log.Printf("failed to listen: %v", err)
// 			return
// 		}

// 		// lis, err := net.Listen("tcp", "localhost:0")
// 		// if err != nil {
// 		// 	log.Fatalf("failed to serve: %v", err)
// 		// }

// 		// Initialize the mashup server configuration and auth
// 		// token.
// 		if maxMessageLength == -2 {
// 			serverConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
// 				AuthToken: "", // server token.
// 				Port:      int64(lis.Addr().(*net.TCPAddr).Port),
// 			}
// 		} else {
// 			serverConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
// 				AuthToken: mashupsdk.GenAuthToken(), // server token.
// 				Port:      int64(lis.Addr().(*net.TCPAddr).Port),
// 			}
// 		}

// 		client.SetServerConfigs(serverConnectionConfigs)

// 		// Connect to the server for purposes of mashup api calls.
// 		mashupCertPool := x509.NewCertPool()
// 		mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
// 		mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
// 		if err != nil {
// 			log.Printf("failed to serve: %v", err)
// 			return
// 		}
// 		mashupCertPool.AddCert(mashupClientCert)

// 		var defaultDialOpt grpc.DialOption = grpc.EmptyDialOption{}

// 		if maxMessageLength > 0 {
// 			defaultDialOpt = grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageLength), grpc.MaxCallSendMsgSize(maxMessageLength))
// 		}
// 		// Send credentials back to client....
// 		conn, err := grpc.Dial("localhost:"+port, defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: insecure}))) //strconv.Itoa(int(handshakeConfigs.Port))
// 		if err != nil {
// 			log.Printf("did not connect: %v", err)
// 			return
// 		}
// 		mashupContext := &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: nil}

// 		// Contact the server and print out its response.
// 		// User's of this library will benefit in following way:
// 		// 1. If current application shuts down, mashup
// 		// will also be told to shut down through Shutdown() api
// 		// call before this app exits.
// 		mashupContext.Client = mashupsdk.NewMashupServerClient(conn)

// 		if mashupContextInitHandler != nil {
// 			mashupContextInitHandler.RegisterContext(mashupContext)
// 		}

// 		go func(mH mashupsdk.MashupApiHandler) {
// 			// Async service initiation.
// 			log.Printf("Start Registering server.\n")
// 			serv := &MashupServer{}
// 			// client.SetHandler(nil, mH)
// 			mashupsdk.RegisterMashupServerServer(s, serv)
// 			curr_server = serv
// 			apihandler = mH
// 			log.Printf("My Starting service.\n")
// 			if err := s.Serve(lis); err != nil {
// 				log.Fatalf("failed to serve: %v", err)
// 			}
// 		}(mapiH)

// 		log.Printf("Handshake initiated.\n")
// 		if maxMessageLength != -2 {
// 			localInitServer(mashupContext, *handshakeConfigs)
// 		}
// 		log.Printf("Handshake complete.\n")

// 	}(mashupApiHandler)
// 	wg.Wait()
// }

// func localInitServer(mashupContext *mashupsdk.MashupContext, handshakeConfigs mashupsdk.MashupConnectionConfigs) {
// 	callerToken := handshakeConfigs.CallerToken
// 	handshakeConfigs.AuthToken = callerToken
// 	handshakeConfigs.CallerToken = serverConnectionConfigs.AuthToken
// 	handshakeConfigs.Port = serverConnectionConfigs.Port
// 	var err error
// 	clientConnectionConfigs, err = mashupContext.Client.CollaborateInit(mashupContext.Context, &handshakeConfigs)
// 	if err != nil {
// 		log.Printf("handshake failure: %v\n", err)
// 		panic(err)
// 	}
// }

// func GetServer() *MashupServer {
// 	return curr_server
// }

// func GetHandler() mashupsdk.MashupApiHandler {
// 	return apihandler
// }

// // InitServer -- bootstraps the server portion of the sdk for the mashup.
// // func InitServer(creds string, insecure bool, maxMessageLength int, mashupApiHandler mashupsdk.MashupApiHandler, mashupContextInitHandler mashupsdk.MashupContextInitHandler) {
// // 	// Perform handshake...
// // 	handshakeConfigs := &sdk.MashupConnectionConfigs{}
// // 	err := json.Unmarshal([]byte(creds), handshakeConfigs)
// // 	if err != nil {
// // 		log.Fatalf("Malformed credentials: %s %v", creds, err)
// // 	}
// // 	log.Printf("Startup with insecure: %t\n", insecure)

// // 	go func(mapiH mashupsdk.MashupApiHandler) {
// // 		mashupCertBytes, err := sdk.MashupCert.ReadFile("tls/mashup.crt")
// // 		if err != nil {
// // 			log.Fatalf("Couldn't load cert: %v", err)
// // 		}

// // 		mashupKeyBytes, err := sdk.MashupKey.ReadFile("tls/mashup.key")
// // 		if err != nil {
// // 			log.Fatalf("Couldn't load key: %v", err)
// // 		}

// // 		cert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
// // 		if err != nil {
// // 			log.Fatalf("Couldn't construct key pair: %v", err)
// // 		}
// // 		creds := credentials.NewServerTLSFromCert(&cert)

// // 		var s *grpc.Server

// // 		if maxMessageLength > 0 {
// // 			s = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
// // 		} else {
// // 			s = grpc.NewServer(grpc.Creds(creds))
// // 		}

// // 		lis, err := net.Listen("tcp", "localhost:0")
// // 		if err != nil {
// // 			log.Fatalf("failed to serve: %v", err)
// // 		}

// // 		// Initialize the mashup server configuration and auth
// // 		// token.
// // 		serverConnectionConfigs = &sdk.MashupConnectionConfigs{
// // 			AuthToken: sdk.GenAuthToken(), // server token.
// // 			Port:      int64(lis.Addr().(*net.TCPAddr).Port),
// // 		}

// // 		// Connect to the server for purposes of mashup api calls.
// // 		mashupCertPool := x509.NewCertPool()
// // 		mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
// // 		mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
// // 		if err != nil {
// // 			log.Fatalf("failed to serve: %v", err)
// // 		}
// // 		mashupCertPool.AddCert(mashupClientCert)

// // 		var defaultDialOpt grpc.DialOption = grpc.EmptyDialOption{}

// // 		if maxMessageLength > 0 {
// // 			defaultDialOpt = grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageLength), grpc.MaxCallSendMsgSize(maxMessageLength))
// // 		}
// // 		// Send credentials back to client....
// // 		conn, err := grpc.Dial("localhost:"+strconv.Itoa(int(handshakeConfigs.Port)), defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: insecure})))
// // 		if err != nil {
// // 			log.Fatalf("did not connect: %v", err)
// // 		}
// // 		mashupContext := &sdk.MashupContext{Context: context.Background(), MashupGoodies: nil}

// // 		// Contact the server and print out its response.
// // 		// User's of this library will benefit in following way:
// // 		// 1. If current application shuts down, mashup
// // 		// will also be told to shut down through Shutdown() api
// // 		// call before this app exits.
// // 		mashupContext.Client = sdk.NewMashupServerClient(conn)

// // 		if mashupContextInitHandler != nil {
// // 			mashupContextInitHandler.RegisterContext(mashupContext)
// // 		}

// // 		go func(mH mashupsdk.MashupApiHandler) {
// // 			// Async service initiation.
// // 			log.Printf("Start Registering server.\n")

// // 			sdk.RegisterMashupServerServer(s, &MashupServer{mashupApiHandler: mH})

// // 			log.Printf("My Starting service.\n")
// // 			if err := s.Serve(lis); err != nil {
// // 				log.Fatalf("failed to serve: %v", err)
// // 			}
// // 		}(mapiH)

// // 		log.Printf("Handshake initiated.\n")

// // 		callerToken := handshakeConfigs.CallerToken
// // 		handshakeConfigs.AuthToken = callerToken
// // 		handshakeConfigs.CallerToken = serverConnectionConfigs.AuthToken
// // 		handshakeConfigs.Port = serverConnectionConfigs.Port

// // 		clientConnectionConfigs, err = mashupContext.Client.CollaborateInit(mashupContext.Context, handshakeConfigs)
// // 		if err != nil {
// // 			log.Printf("handshake failure: %v\n", err)
// // 			panic(err)
// // 		}
// // 		log.Printf("Handshake complete.\n")

// // 	}(mashupApiHandler)
// // }
