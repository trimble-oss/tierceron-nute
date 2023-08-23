package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/trimble-oss/tierceron-nute/mashupsdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client bootstrapping is concerned with establishing connection with
// mashup, handshaking, and establishing credential sets.  It
// also sets up signal handling in event of either system
// shutting down.
var handshakeConnectionConfigs *mashupsdk.MashupConnectionConfigs
var clientConnectionConfigs *mashupsdk.MashupConnectionConfigs
var serverConnectionConfigs *mashupsdk.MashupConnectionConfigs

var mashupContext *mashupsdk.MashupContext
var insecure *bool

var handshakeCompleteChan chan bool

var mashupCertBytes []byte

// forkMashup -- starts mashup
func forkMashup(mashupGoodies map[string]interface{}) error {
	// exPath string, envParams []string, params []string

	var procAttr = syscall.ProcAttr{
		Dir:   ".",
		Env:   append([]string{"DISPLAY=:0.0"}, mashupGoodies["ENV"].([]string)...),
		Files: nil,
		Sys: &syscall.SysProcAttr{
			Setsid:     true,
			Foreground: false,
		},
	}
	params := []string{mashupGoodies["MASHUP_PATH"].(string)}
	params = append(params, mashupGoodies["PARAMS"].([]string)...)
	mashupPath, lookupErr := exec.LookPath(mashupGoodies["MASHUP_PATH"].(string))
	if lookupErr != nil {
		log.Fatalf("Couldn't exec mashup: %v", lookupErr)
	}

	var pid, forkErr = syscall.ForkExec(mashupPath, params, &procAttr)
	if forkErr != nil {
		log.Fatalf("Couldn't exec mashup: %v", forkErr)
	}
	log.Println("Spawned proc", pid)
	mashupGoodies["PID"] = pid

	return forkErr
}

// remoteInitContext -- Initializes client with provided client and remote server addresses and auth token from mashupGoodies
// Returns the mashupContext associated with this client
func remoteInitContext(mashupApiHandler mashupsdk.MashupApiHandler,
	mashupGoodies map[string]interface{}) *mashupsdk.MashupContext {
	log.Printf("Initializing Remote Mashup. \n")
	handshakeCompleteChan = make(chan bool)
	var err error
	mashupContext = &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: mashupGoodies}
	insecure = mashupGoodies["tls-skip-validation"].(*bool)
	var maxMessageLength int = -1
	if mml, mmlOk := mashupGoodies["maxMessageLength"].(int); mmlOk {
		maxMessageLength = mml
	}

	server_name := ""
	handshake_name := ""
	port := 0
	if env, envOk := mashupGoodies["ENV"].([]string); envOk {
		if len(env) > 2 {
			server_name = env[0]
			port, err = strconv.Atoi(env[1])
			if err != nil {
				log.Printf("Failed to convert port: %v", err)
			}
			handshake_name = env[2]
		} else {
			log.Printf("Invalid environment specified for remote server. Make sure the environment parameter is in the following order: [remote server name, remote server port, client server name]")
			return nil
		}
	} else {
		log.Printf("Client server name not specified")
		return nil
	}

	auth_token := ""
	if params, paramsOk := mashupGoodies["PARAMS"].([]string); paramsOk {
		if len(params) > 1 {
			auth_token = params[1]
		} else {
			log.Printf("No auth token provided by client")
			return nil
		}
	} else {
		log.Printf("No auth token provided by client")
		return nil
	}

	mashupCertBytes, err = mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
	if err != nil {
		log.Printf("Couldn't load cert: %v", err)
		return nil
	}

	mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
	if err != nil {
		log.Printf("Couldn't load key: %v", err)
		return nil
	}

	serverCert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
	if err != nil {
		log.Printf("failed to serve: %v", err)
		return nil
	}
	creds := credentials.NewServerTLSFromCert(&serverCert)

	var handshakeServer *grpc.Server
	if maxMessageLength > 0 {
		handshakeServer = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
	} else {
		handshakeServer = grpc.NewServer(grpc.Creds(creds))
	}
	lis, err := net.Listen("tcp", handshake_name+":0")
	if err != nil {
		log.Printf("Failed to serve: %v", err)
		return nil
	}
	handshakeConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
		AuthToken: auth_token,     // Provided by the client
		Server:    handshake_name, // Provided by the client
		Port:      int64(lis.Addr().(*net.TCPAddr).Port),
	}

	go func(handler mashupsdk.MashupApiHandler) {
		if maxMessageLength > 0 {
			InitDialOptions(grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageLength), grpc.MaxCallSendMsgSize(maxMessageLength)))
		}
		mashupsdk.RegisterMashupServerServer(handshakeServer, &MashupClient{mashupApiHandler: handler})
		handshakeServer.Serve(lis)
	}(mashupApiHandler)

	mashupCertPool := x509.NewCertPool()
	mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
	mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
	if err != nil {
		log.Printf("failed to serve: %v", err)
	}
	mashupCertPool.AddCert(mashupClientCert)

	conn, err := grpc.Dial(server_name+":"+strconv.Itoa(int(port)), grpc.EmptyDialOption{}, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: *insecure})))
	if err != nil {
		log.Printf("did not connect: %v", err)
		return nil
	}
	c := mashupsdk.NewMashupServerClient(conn)

	mashupCtx := &mashupsdk.MashupContext{Context: context.Background(), Client: c}
	c.CollaborateBootstrap(mashupCtx, handshakeConnectionConfigs)

	<-handshakeCompleteChan
	log.Printf("Mashup initialized.\n")

	return mashupContext
}

func initContext(mashupApiHandler mashupsdk.MashupApiHandler,
	mashupGoodies map[string]interface{}) *mashupsdk.MashupContext {
	log.Printf("Initializing Mashup.\n")

	handshakeCompleteChan = make(chan bool)
	var err error
	mashupContext = &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: mashupGoodies}
	insecure = mashupGoodies["tls-skip-validation"].(*bool)
	var maxMessageLength int = -1
	if mml, mmlOk := mashupGoodies["maxMessageLength"].(int); mmlOk {
		maxMessageLength = mml
	}
	// If no server name is specified, defaults to localhost
	var local_server string
	if env_params, envOk := mashupGoodies["ENV"].([]string); envOk {
		if len(env_params) > 0 {
			local_server = env_params[0]
		}
	} else {
		local_server = "localhost"
	}

	// Initialize local server.
	mashupCertBytes, err = mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
	if err != nil {
		log.Fatalf("Couldn't load cert: %v", err)
	}

	mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
	if err != nil {
		log.Fatalf("Couldn't load key: %v", err)
	}

	serverCert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
	if err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
	creds := credentials.NewServerTLSFromCert(&serverCert)

	var handshakeServer *grpc.Server
	if maxMessageLength > 0 {
		handshakeServer = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
	} else {
		handshakeServer = grpc.NewServer(grpc.Creds(creds))
	}
	lis, err := net.Listen("tcp", local_server+":0")
	data := make([]byte, 10)
	for i := range data {
		data[i] = byte(rand.Intn(256))
	}
	randomSha256 := sha256.Sum256(data)
	handshakeConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
		AuthToken: string(hex.EncodeToString([]byte(randomSha256[:]))),
		Port:      int64(lis.Addr().(*net.TCPAddr).Port),
	}

	forkConnectionConfigs := &mashupsdk.MashupConnectionConfigs{
		CallerToken: handshakeConnectionConfigs.AuthToken,
		Port:        handshakeConnectionConfigs.Port,
	}

	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
	go func(handler mashupsdk.MashupApiHandler) {
		if maxMessageLength > 0 {
			InitDialOptions(grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageLength), grpc.MaxCallSendMsgSize(maxMessageLength)))
		}
		mashupsdk.RegisterMashupServerServer(handshakeServer, &MashupClient{mashupApiHandler: handler})
		handshakeServer.Serve(lis)
	}(mashupApiHandler)

	jsonHandshakeCredentials, err := json.Marshal(forkConnectionConfigs)
	if err != nil {
		log.Fatalf("Failure to launch: %v", err)
	}
	// Setup the onetime use handshake token...
	mashupGoodies["PARAMS"] = append(mashupGoodies["PARAMS"].([]string), "-CREDS="+string(jsonHandshakeCredentials))
	mashupGoodies["PARAMS"] = append(mashupGoodies["PARAMS"].([]string), "-tls-skip-validation=true")

	// Start mashup..
	err = forkMashup(mashupGoodies)
	if err != nil {
		log.Fatalf("Failure to launch: %v", err)
	}

	<-handshakeCompleteChan
	log.Printf("Mashup initialized.\n")

	return mashupContext
}

// For a remote server/client initialization, ensure envParams is of the format:
// [remote server name, remote server port, client server name]
// Also for a remote server/client initialization,
// ensure params is of the format: ["remote", Remote server auth token]
func BootstrapInit(mashupPath string,
	mashupApiHandler mashupsdk.MashupApiHandler,
	envParams []string,
	params []string,
	insecure *bool) *mashupsdk.MashupContext {
	return BootstrapInitWithMessageExt(mashupPath, mashupApiHandler, envParams, params, insecure, -1)
}

// BootstrapInitWithMessageExt - main entry point for bootstrapping the sdk.
// This will fork a mashup, connect with it, and handshake with
// it to establish shared set of credentials to be used in
// future transactions.
func BootstrapInitWithMessageExt(mashupPath string,
	mashupApiHandler mashupsdk.MashupApiHandler,
	envParams []string,
	params []string,
	insecure *bool, maxMessageLength int) *mashupsdk.MashupContext {

	mashupGoodies := map[string]interface{}{}
	mashupGoodies["MASHUP_PATH"] = mashupPath
	if envParams == nil {
		envParams = []string{}
	}
	mashupGoodies["ENV"] = envParams
	remote := false
	if len(params) > 1 {
		if params[0] == "remote" {
			remote = true
		}
	}
	mashupGoodies["PARAMS"] = params
	mashupGoodies["tls-skip-validation"] = insecure
	mashupGoodies["maxMessageLength"] = maxMessageLength
	if remote {
		return remoteInitContext(mashupApiHandler, mashupGoodies)
	} else {
		return initContext(mashupApiHandler, mashupGoodies)
	}
}
