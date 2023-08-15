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
	sdk "github.com/trimble-oss/tierceron-nute/mashupsdk"
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
func ForkMashup(mashupGoodies map[string]interface{}) error {
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

func localBootstrapInit(mashupApiHandler sdk.MashupApiHandler, mashupGoodies map[string]interface{}) *sdk.MashupContext {
	log.Printf("Initializing Local Mashup.\n")

	var maxMessageLength int

	mashupKeyBytes, err := mashupsdk.MashupKey.ReadFile("tls/mashup.key")
	if err != nil {
		log.Fatalf("Couldn't load key: %v", err)
	}

	serverCert, err := tls.X509KeyPair(mashupCertBytes, mashupKeyBytes)
	if err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
	creds := credentials.NewServerTLSFromCert(&serverCert)

	var grpcserver *grpc.Server
	if maxMessageLength > 0 {
		grpcserver = grpc.NewServer(grpc.MaxRecvMsgSize(maxMessageLength), grpc.MaxSendMsgSize(maxMessageLength), grpc.Creds(creds))
	} else {
		grpcserver = grpc.NewServer(grpc.Creds(creds))
	}
	lis, err := net.Listen("tcp", "localhost:0")

	data := make([]byte, 10)
	for i := range data {
		data[i] = byte(rand.Intn(256))
	}
	randomSha256 := sha256.Sum256(data)
	connectionConfigs := &mashupsdk.MashupConnectionConfigs{
		AuthToken: string(hex.EncodeToString([]byte(randomSha256[:]))),
		Port:      int64(lis.Addr().(*net.TCPAddr).Port),
	}

	serverConnectionConfigs = connectionConfigs
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
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
	conn, err := grpc.Dial("localhost:"+strconv.Itoa(int(connectionConfigs.Port)), defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: *insecure})))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	// Contact the server and print out its response.
	// User's of this library will benefit in following way:
	// 1. If current application shuts down, mashup
	// will also be told to shut down through Shutdown() api
	// call before this app exits.
	mashupContext.Client = mashupsdk.NewMashupServerClient(conn)

	go func(handler mashupsdk.MashupApiHandler, serv *grpc.Server, maxMessageLength int, lis net.Listener) {
		if maxMessageLength > 0 {
			InitDialOptions(grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageLength), grpc.MaxCallSendMsgSize(maxMessageLength)))
		}
		mashupsdk.RegisterMashupServerServer(grpcserver, &MashupClient{mashupApiHandler: handler})
		grpcserver.Serve(lis)
	}(mashupApiHandler, grpcserver, maxMessageLength, lis)

	handshakeCompleteChan = make(chan bool)
	handshakeConnectionConfigs = connectionConfigs
	forkConnectionConfigs := &mashupsdk.MashupConnectionConfigs{
		CallerToken: handshakeConnectionConfigs.AuthToken,
		Port:        handshakeConnectionConfigs.Port,
	}

	jsonHandshakeCredentials, err := json.Marshal(forkConnectionConfigs)
	if err != nil {
		log.Fatalf("Failure to launch: %v", err)
	}
	// Setup the onetime use handshake token...
	mashupGoodies["PARAMS"] = append(mashupGoodies["PARAMS"].([]string), "-CREDS="+string(jsonHandshakeCredentials))
	mashupGoodies["PARAMS"] = append(mashupGoodies["PARAMS"].([]string), "-tls-skip-validation=true")

	// Start mashup..
	err = ForkMashup(mashupGoodies)
	if err != nil {
		log.Fatalf("Failure to launch: %v", err)
	}

	<-handshakeCompleteChan
	log.Printf("Local Mashup initialized.\n")
	return mashupContext
}

func commonInitContext(mashupApiHandler mashupsdk.MashupApiHandler, mashupGoodies map[string]interface{}) *mashupsdk.MashupContext {
	mashupCertBytes, err := mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
	if err != nil {
		log.Printf("Couldn't load cert: %v", err)
		return nil
	}

	log.Printf("Initializing Mashup.\n")

	// var err error
	mashupContext = &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: mashupGoodies}
	insecure = mashupGoodies["tls-skip-validation"].(*bool)
	var maxMessageLength int = -1
	if mml, mmlOk := mashupGoodies["maxMessageLength"].(int); mmlOk {
		maxMessageLength = mml
	}

	mashupCertBytes, err = mashupsdk.MashupCert.ReadFile("tls/mashup.crt")
	if err != nil {
		log.Fatalf("Couldn't load cert: %v", err)
	}

	if maxMessageLength == -2 {
		serverConnectionConfigs = &mashupsdk.MashupConnectionConfigs{
			AuthToken: "c5376ccf9edc2a02499716c7e4f5599e8a96747e8a762c8ebed7a45074ad192a", // server token.
			Port:      8080,
		}
		// client.SetServerConfigs(serverConnectionConfigs)
		// server.SetServerConfigs(serverConnectionConfigs)
		mashupCertPool := x509.NewCertPool()
		mashupBlock, _ := pem.Decode([]byte(mashupCertBytes))
		mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
		if err != nil {
			log.Printf("failed to serve: %v", err)
		}
		mashupCertPool.AddCert(mashupClientCert)
		conn, err := grpc.Dial("localhost:8080", grpc.EmptyDialOption{}, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: *insecure})))
		if err != nil {
			log.Fatalf("did not connect: %v", err)
		}
		c := mashupsdk.NewMashupServerClient(conn)
		mashupCtx := &mashupsdk.MashupContext{Context: context.Background(), Client: c}
		return mashupCtx
	}

	return localBootstrapInit(mashupApiHandler, mashupGoodies)
}

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
	mashupGoodies["PARAMS"] = params
	mashupGoodies["tls-skip-validation"] = insecure
	mashupGoodies["maxMessageLength"] = maxMessageLength

	return commonInitContext(mashupApiHandler, mashupGoodies)
}

func GetServerConfigs() *mashupsdk.MashupConnectionConfigs {
	return serverConnectionConfigs
}
