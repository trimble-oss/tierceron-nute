package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/trimble-oss/tierceron-nute/mashupsdk"
	sdk "github.com/trimble-oss/tierceron-nute/mashupsdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// server is used to implement server.MashupServer.
type MashupServer struct {
	sdk.UnimplementedMashupServerServer
	mashupApiHandler mashupsdk.MashupApiHandler
}

func GetClientAuthToken() string {
	if clientConnectionConfigs != nil {
		return clientConnectionConfigs.AuthToken
	} else {
		return ""
	}
}

func GetServerAuthToken() string {
	if serverConnectionConfigs != nil {
		return serverConnectionConfigs.AuthToken
	} else {
		return ""
	}
}

// Shutdown -- handles request to shut down the mashup.
func (s *MashupServer) Shutdown(ctx context.Context, in *sdk.MashupEmpty) (*sdk.MashupEmpty, error) {
	log.Println("Shutdown called")
	if in.GetAuthToken() != serverConnectionConfigs.AuthToken {
		return nil, errors.New("Auth failure")
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		log.Printf("Server shutting down.")
		os.Exit(-1)
	}()

	log.Println("Shutdown complete.")
	return &sdk.MashupEmpty{}, nil
}

// CollaborateBootstrap -- Alerts server to existence of client and server calls to client to connect
func (s *MashupServer) CollaborateBootstrap(ctx context.Context, in *sdk.MashupConnectionConfigs) (*sdk.MashupEmpty, error) {
	log.Println("CollaborateBootstrap called")
	if in.GetAuthToken() != serverConnectionConfigs.AuthToken {
		return nil, errors.New("auth failure")
	}
	mashupCertPool := x509.NewCertPool()
	mashupBlock, _ := pem.Decode([]byte(mashupsdk.MashupCertBytes))
	mashupClientCert, err := x509.ParseCertificate(mashupBlock.Bytes)
	if err != nil {
		log.Printf("failed to serve: %v", err)
		return nil, err
	}
	mashupCertPool.AddCert(mashupClientCert)

	var defaultDialOpt grpc.DialOption = grpc.EmptyDialOption{}

	if maxMessage > 0 {
		defaultDialOpt = grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessage), grpc.MaxCallSendMsgSize(maxMessage))
	}
	// Send credentials back to client....
	remote_conn, err := grpc.Dial(in.Server+":"+strconv.Itoa(int(in.Port)), defaultDialOpt, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: mashupCertPool, InsecureSkipVerify: security})))
	if err != nil {
		log.Printf("did not connect: %v", err)
		return nil, err
	}

	mashupContext := &mashupsdk.MashupContext{Context: context.Background(), MashupGoodies: nil}
	mashupContext.Client = mashupsdk.NewMashupServerClient(remote_conn)

	if initHandler != nil {
		initHandler.RegisterContext(mashupContext)
	}
	clientConnectionConfigs, err = mashupContext.Client.CollaborateInit(mashupContext.Context, serverConnectionConfigs)
	if err != nil {
		log.Printf("handshake failure: %v\n", err)
		return nil, err
	}

	log.Println("Handshake complete.")
	return &sdk.MashupEmpty{}, nil
}

func (s *MashupServer) ResetStates(ctx context.Context, in *sdk.MashupEmpty) (*emptypb.Empty, error) {
	log.Println("ResetStates called")
	if in.GetAuthToken() != serverConnectionConfigs.AuthToken {
		return nil, errors.New("Auth failure")
	}
	if s.mashupApiHandler != nil {
		log.Printf("Delegate to api handler.")
		s.mashupApiHandler.ResetStates()
	}

	log.Println("ResetStates complete.")
	return &emptypb.Empty{}, nil
}

// OnDisplayChange -- handles a request from the client to resize.
func (s *MashupServer) OnDisplayChange(ctx context.Context, in *sdk.MashupDisplayBundle) (*sdk.MashupDisplayHint, error) {
	log.Printf("OnDisplayChange called")
	if in.GetAuthToken() != serverConnectionConfigs.AuthToken {
		log.Printf("OnDisplayChange auth failure.")
		return nil, errors.New("Auth failure")
	}
	displayHint := in.MashupDisplayHint
	log.Printf("Received resize: %d %d %d %d\n", displayHint.Xpos, displayHint.Ypos, displayHint.Width, displayHint.Height)

	if s.mashupApiHandler != nil {
		log.Printf("Delegate to api handler.")
		s.mashupApiHandler.OnDisplayChange(displayHint)
	}

	log.Printf("Finished OnDisplayChange")
	return displayHint, nil
}

func (s *MashupServer) GetElements(ctx context.Context, in *sdk.MashupEmpty) (*sdk.MashupDetailedElementBundle, error) {
	log.Printf("GetElements called")
	if in.GetAuthToken() != serverConnectionConfigs.AuthToken {
		return nil, errors.New("Auth failure")
	}
	if s.mashupApiHandler != nil {
		log.Printf("GetElements Delegate to api handler.")
		return s.mashupApiHandler.GetElements()
	}
	return nil, status.Errorf(codes.Unimplemented, "method GetMashupElements not implemented")
}

func (s *MashupServer) UpsertElements(ctx context.Context, in *sdk.MashupDetailedElementBundle) (*sdk.MashupDetailedElementBundle, error) {
	log.Printf("UpsertElements called")
	if in.GetAuthToken() != serverConnectionConfigs.AuthToken {
		return nil, errors.New("Auth failure")
	}
	if s.mashupApiHandler != nil {
		log.Printf("UpsertElements Delegate to api handler.")
		return s.mashupApiHandler.UpsertElements(in)
	}
	return nil, status.Errorf(codes.Unimplemented, "method UpsertElements not implemented")
}

func (s *MashupServer) TweakStates(ctx context.Context, in *sdk.MashupElementStateBundle) (*sdk.MashupElementStateBundle, error) {
	log.Printf("TweakStates called")
	if in.GetAuthToken() != serverConnectionConfigs.AuthToken {
		log.Printf("TweakStates Auth failure.")
		return nil, errors.New("Auth failure")
	}
	if s.mashupApiHandler != nil {
		log.Printf("TweakStates Delegate to api handler.")
		return s.mashupApiHandler.TweakStates(in)
	}
	return nil, nil
}

func (s *MashupServer) SetHandler(mashupApiHandler mashupsdk.MashupApiHandler) {
	log.Printf("SetHandler called")
	// if s == nil {
	// 	curr_server.mashupApiHandler = mashupApiHandler
	// } else {
	// 	s.mashupApiHandler = mashupApiHandler
	// }
}

func SetServerConfigs(serverconfigs *sdk.MashupConnectionConfigs) {
	serverConnectionConfigs = serverconfigs
}

func (c *MashupServer) TweakStatesByMotiv(ctx context.Context, in *mashupsdk.Motiv) (*emptypb.Empty, error) {
	log.Printf("TweakStatesByMotiv called")
	if in.GetAuthToken() != serverConnectionConfigs.AuthToken {
		log.Printf("Auth failure.")
		return nil, errors.New("Auth failure")
	}
	if c.mashupApiHandler != nil {
		log.Printf("TweakStatesByMotiv Delegate to api handler.")
		return c.mashupApiHandler.TweakStatesByMotiv(in)
	} else {
		log.Printf("TweakStatesByMotiv No api handler provided.")
	}
	return nil, nil
}
