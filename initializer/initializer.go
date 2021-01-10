package initializer

import (
	"context"
	"errors"
	"fmt"
	"github.com/lightninglabs/pool/poolrpc"
	"sync/atomic"
)

var (
	// ErrInitTimeout signals that we did not get the expected init
	// message before the timeout occurred.
	ErrInitTimeout = errors.New("got no init message before timeout")
)

type InitMsg struct {
	StatelessInit  bool
	LndAuthDetails *LndAuthDetails
}

type LndAuthDetails struct {
	Host          string
	Port          int64
	AdminMacaroon string
	TlsCert       string
}

type InitResponse struct {
	InitSucceeded bool
	PooldMacaroon []byte
	InitError     string
}

type PooldInitializerResponse struct {
	StatelessInit  bool
	LndAuthDetails *LndAuthDetails
}

type PooldInitializerService struct {
	InitMsgs        chan *InitMsg
	InitResponses   chan *PooldInitializerResponse
	MacResponseChan chan []byte
	// Must be used atomically.
	ServiceInitialized *int32
}

func New() *PooldInitializerService {
	return &PooldInitializerService{
		InitMsgs:        make(chan *InitMsg, 1),
		InitResponses:   make(chan *PooldInitializerResponse, 1),
		MacResponseChan: make(chan []byte, 1),
	}
}

func (ps *PooldInitializerService) InitializeService(ctx context.Context,
	in *poolrpc.InitializeRequest) (*poolrpc.InitializeResponse, error) {

	if atomic.AddInt32(ps.ServiceInitialized, 1) != 1 {
		return nil, fmt.Errorf("poold service already initialized")
	}

	return nil, nil
}

func validateLndAuthDetails(in *poolrpc.LndAuthDetails) error {
	var validateError error

	switch {
	case in == nil:
		validateError = fmt.Errorf("param LndAuthDetails not provided")
	case in.Host == "":
		validateError = fmt.Errorf("no lnd host provided in LndAuthDetails")
	case in.AdminMacaroon == "":
		validateError = fmt.Errorf("no lnd admin macaroon provided in LndAuthDetails")
	case in.TlsCert == "":
		validateError = fmt.Errorf("no lnd tls cert provided in LndAuthDetails")
	}

	return validateError
}
