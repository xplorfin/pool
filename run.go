package pool

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	proxy "github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/lightninglabs/pool/initializer"
	"github.com/lightninglabs/pool/keychain"
	"github.com/lightninglabs/pool/poolrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/signal"
)

type LndAuthDetails struct {
	Host          string
	Port          int64
	AdminMacaroon string
	TlsCert       string
}

// GrpcRegistrar is an interface that must be satisfied by an external subserver
// that wants to be able to register its own gRPC server onto lnd's main
// grpc.Server instance.
type GrpcRegistrar interface {
	// RegisterGrpcSubserver is called for each net.Listener on which lnd
	// creates a grpc.Server instance. External subservers implementing this
	// method can then register their own gRPC server structs to the main
	// server instance.
	RegisterGrpcSubserver(*grpc.Server) error
}

// RestRegistrar is an interface that must be satisfied by an external subserver
// that wants to be able to register its own REST mux onto lnd's main
// proxy.ServeMux instance.
type RestRegistrar interface {
	// RegisterRestSubserver is called after lnd creates the main
	// proxy.ServeMux instance. External subservers implementing this method
	// can then register their own REST proxy stubs to the main server
	// instance.
	RegisterRestSubserver(context.Context, *proxy.ServeMux, string,
		[]grpc.DialOption) error
}

// RPCSubserverConfig is a struct that can be used to register an external
// subserver with the custom permissions that map to the gRPC server that is
// going to be registered with the GrpcRegistrar.
type RPCSubserverConfig struct {
	// Registrar is a callback that is invoked for each net.Listener on
	// which lnd creates a grpc.Server instance.
	Registrar GrpcRegistrar

	// Permissions is the permissions required for the external subserver.
	// It is a map between the full HTTP URI of each RPC and its required
	// macaroon permissions. If multiple action/entity tuples are specified
	// per URI, they are all required. See rpcserver.go for a list of valid
	// action and entity values.
	Permissions map[string][]bakery.Op

	// MacaroonValidator is a custom macaroon validator that should be used
	// instead of the default lnd validator. If specified, the custom
	// validator is used for all URIs specified in the above Permissions
	// map.
	MacaroonValidator macaroons.MacaroonValidator
}

// ListenerWithSignal is a net.Listener that has an additional Ready channel that
// will be closed when a server starts listening.
type ListenerWithSignal struct {
	net.Listener

	// Ready will be closed by the server listening on Listener.
	Ready chan struct{}

	// ExternalRPCSubserverCfg is optional and specifies the registration
	// callback and permissions to register external gRPC subservers.
	ExternalRPCSubserverCfg *RPCSubserverConfig

	// ExternalRestRegistrar is optional and specifies the registration
	// callback to register external REST subservers.
	ExternalRestRegistrar RestRegistrar
}

// ListenerCfg is a wrapper around custom listeners that can be passed to lnd
// when calling its main method.
type ListenerCfg struct {
	// WalletUnlocker can be set to the listener to use for the wallet
	// unlocker. If nil a regular network listener will be created.
	WalletUnlocker *ListenerWithSignal

	// RPCListener can be set to the listener to use for the RPC server. If
	// nil a regular network listener will be created.
	RPCListener *ListenerWithSignal
}

// tcpListener is a function type used for closures that fetches a RPC
// listener for the current configuration. If no custom listener is present,
// this should return a normal listener from the RPC endpoints defined in the
// config. The second return value us a closure that will close the fetched
// listener.
type tcpListener func() (*ListenerWithSignal, func(), error)

type InitializerParams struct {
	StatelessInit   bool
	LndAuthDetails  *LndAuthDetails
	MacResponseChan chan []byte
}

// Main starts the trader daemon and blocks until it's shut down again.
func Main(cfg *Config) error {
	var lndAuthDetails *LndAuthDetails

	// Initialize logging at the default logging level.
	err := logWriter.InitLogRotator(
		filepath.Join(cfg.LogDir, DefaultLogFilename),
		cfg.MaxLogFileSize, cfg.MaxLogFiles,
	)
	if err != nil {
		return err
	}
	err = build.ParseAndSetDebugLevels(cfg.DebugLevel, logWriter)
	if err != nil {
		return err
	}

	err = signal.Intercept()
	if err != nil {
		return err
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	restProxyDest := cfg.RPCListen

	var (
		serverTLSCfg    *tls.Config
		restClientCreds *credentials.TransportCredentials
	)

	// The real KeyRing isn't available until after the wallet is unlocked,
	// but we need one now. Because we aren't encrypting anything here it can
	// be an empty KeyRing.
	var emptyKeyRing keychain.KeyRing
	// If --tlsencryptkey is set then generate a throwaway TLS pair in memory
	// so we can still have TLS even though the wallet isn't unlocked. These
	// get thrown away for the real certificates once the wallet is unlocked.
	// If TLSEncryptKey is false, then get the TLSConfig like normal.
	// We'll need to start the server with TLS and connect the REST proxy
	// client to it.
	//if cfg.TLSEncryptKey {
	//	serverTLSCfg, restClientCreds, err = getEphemeralTLSConfig(cfg)
	//} else {
	//
	//}

	serverTLSCfg, restClientCreds, err = getTLSConfig(cfg, emptyKeyRing)
	if err != nil {
		return fmt.Errorf("could not create gRPC server options: %v",
			err)
	}

	switch {
	case strings.Contains(restProxyDest, "0.0.0.0"):
		restProxyDest = strings.Replace(
			restProxyDest, "0.0.0.0", "127.0.0.1", 1,
		)

	case strings.Contains(restProxyDest, "[::]"):
		restProxyDest = strings.Replace(
			restProxyDest, "[::]", "[::1]", 1,
		)
	}

	serverCreds := credentials.NewTLS(serverTLSCfg)
	serverOpts := []grpc.ServerOption{grpc.Creds(serverCreds)}

	// For our REST dial options, we'll still use TLS, but also increase
	// the max message size that we'll decode to allow clients to hit
	// endpoints which return more data such as the DescribeGraph call.
	// We set this to 200MiB atm. Should be the same value as maxMsgRecvSize
	// in cmd/lncli/main.go.
	restDialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(*restClientCreds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200),
		),
	}

	// getRpcListener is a closure that creates a listener from the
	// RPCListener defined in the config. It also returns a cleanup
	// closure and the server options to use for the GRPC server.
	getRpcListener := func() (*ListenerWithSignal, func(), error) {
		var grpcListener *ListenerWithSignal
		// Start a gRPC server listening for HTTP/2
		// connections.
		lis, err := net.Listen("tcp", cfg.RPCListen)
		if err != nil {
			log.Errorf("unable to listen on %s",
				cfg.RPCListen)
			return nil, nil, err
		}
		grpcListener = &ListenerWithSignal{
			Listener: lis,
			Ready:    make(chan struct{}),
		}

		cleanup := func() {
			_ = lis.Close()
		}

		return grpcListener, cleanup, nil
	}

	getRestListener := func() (*ListenerWithSignal, func(), error) {
		var restListener *ListenerWithSignal
		// Start a gRPC server listening for HTTP/2
		// connections.
		lis, err := tls.Listen("tcp", cfg.RESTListen, serverTLSCfg)
		if err != nil {
			log.Errorf("unable to listen on %s",
				cfg.RESTListen)
			return nil, nil, err
		}
		restListener = &ListenerWithSignal{
			Listener: lis,
			Ready:    make(chan struct{}),
		}

		cleanup := func() {
			_ = lis.Close()
		}

		return restListener, cleanup, nil
	}

	getInitializerListener := func() (*ListenerWithSignal, func(), error) {
		var initializerListener *ListenerWithSignal

		lis, err := net.Listen("tcp", cfg.RPCListen)
		if err != nil {
			log.Errorf("unable to listen on %s",
				cfg.RPCListen)
			return nil, nil, err
		}

		initializerListener = &ListenerWithSignal{
			Listener: lis,
			Ready:    make(chan struct{}),
		}

		cleanup := func() {
			_ = lis.Close()
		}

		return initializerListener, cleanup, nil
	}

	var initializerParams *InitializerParams

	// If --tlsencryptkey is set, we previously generated a throwaway TLSConfig
	// Now we want to remove that and load the persistent TLSConfig
	// The wallet is unlocked at this point so we can use the real KeyRing
	if cfg.TLSEncryptKey {
		tmpCertPath := cfg.TLSCertPath + ".tmp"
		tmpExternalCertPath := fmt.Sprintf("%s/%s/tls.cert.tmp", cfg.BaseDir, cfg.ExternalSSLProvider)

		err = os.Remove(tmpCertPath)
		if err != nil {
			log.Warn("unable to delete temp cert at %v", tmpCertPath)
		}

		err = os.Remove(tmpExternalCertPath)
		if err != nil {
			log.Warn("unable to delete temp external cert at %v", tmpExternalCertPath)
		}

		serverTLSCfg, restClientCreds, err = getTLSConfig(cfg, emptyKeyRing)
		if err != nil {
			err := fmt.Errorf("unable to load TLS credentials: %v", err)
			log.Error(err)
			return err
		}
	}

	traderServer := NewServer(cfg, serverTLSCfg, restProxyDest, *restClientCreds, getRpcListener, getRestListener)

	poolMacBytes, err := traderServer.startMacaroonService(cfg.StatelessInit)
	if err != nil {
		return err
	}
	traderServer.shutdownFuncs["macaroon"] = traderServer.stopMacaroonService

	if cfg.StatelessInit {
		params, shutdown, initializerErr := waitForServiceInit(
			serverOpts, restDialOpts, getInitializerListener,
			getRestListener, restProxyDest,
		)

		if initializerErr != nil {
			return fmt.Errorf("unable to initialize poold service :(")
		}

		lndAuthDetails = params.LndAuthDetails
		initializerParams = params

		initializerParams.MacResponseChan <- poolMacBytes

		shutdown()

		cfg.Lnd = &LndConfig{
			Host:        fmt.Sprintf("%[1]s:%[2]d", lndAuthDetails.Host, lndAuthDetails.Port),
			RawMacaroon: lndAuthDetails.AdminMacaroon,
			RawTLSCert:  lndAuthDetails.TlsCert,
		}
	}

	err = traderServer.Start()
	if err != nil {
		return fmt.Errorf("unable to start server: %v", err)
	}

	<-signal.ShutdownChannel()

	return traderServer.Stop()
}

func waitForServiceInit(serverOpts []grpc.ServerOption,
	restDialOpts []grpc.DialOption, getRpcListener tcpListener,
	getRestListener tcpListener,
	restProxyDest string) (*InitializerParams, func(), error) {

	initializerService := initializer.New()

	grpcServer := grpc.NewServer(serverOpts...)
	poolrpc.RegisterInitializerServer(grpcServer, initializerService)

	var shutdownFuncs []func()
	initializerCleanup := func() {
		// Make sure nothing blocks on reading on the macaroon channel,
		// otherwise the GracefulStop below will never return.
		close(initializerService.MacResponseChan)

		for _, shutdownFn := range shutdownFuncs {
			shutdownFn()
		}
	}
	shutdownFuncs = append(shutdownFuncs, grpcServer.GracefulStop)

	rpcListener, rpcCleanup, err := getRpcListener()
	if err != nil {
		return nil, initializerCleanup, err
	}
	shutdownFuncs = append(shutdownFuncs, rpcCleanup)

	// Use a WaitGroup so we can be sure the instructions on how to input the
	// password is the last thing to be printed to the console.
	var wg sync.WaitGroup

	wg.Add(1)
	go func(lis *ListenerWithSignal) {
		log.Infof("Initializer RPC server listening on %s",
			lis.Addr())

		// Close the ready chan to indicate we are listening.
		close(lis.Ready)

		wg.Done()
		_ = grpcServer.Serve(lis)
	}(rpcListener)

	restCtx := context.Background()
	restCtx, restCancel := context.WithCancel(restCtx)
	shutdownFuncs = append(shutdownFuncs, restCancel)

	mux := proxy.NewServeMux()

	err = poolrpc.RegisterInitializerHandlerFromEndpoint(
		restCtx, mux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return nil, initializerCleanup, err
	}

	srv := &http.Server{Handler: allowCORS(mux, []string{"*"})}

	restListener, restCleanup, err := getRestListener()
	if err != nil {
		return nil, nil, err
	}
	shutdownFuncs = append(shutdownFuncs, restCleanup)

	wg.Add(1)
	go func() {
		log.Infof("Initializer gRPC proxy started at %s",
			restListener.Addr())
		wg.Done()
		_ = srv.Serve(restListener)
	}()

	wg.Wait()

	select {
	case initResponse := <-initializerService.InitResponses:
		return &InitializerParams{
			StatelessInit: initResponse.StatelessInit,
			LndAuthDetails: &LndAuthDetails{
				Host:          initResponse.LndAuthDetails.Host,
				Port:          initResponse.LndAuthDetails.Port,
				AdminMacaroon: initResponse.LndAuthDetails.AdminMacaroon,
				TlsCert:       initResponse.LndAuthDetails.TlsCert,
			},
			MacResponseChan: initializerService.MacResponseChan,
		}, initializerCleanup, nil
	case <-signal.ShutdownChannel():
		return nil, initializerCleanup, fmt.Errorf("shutting down")
	}
}

// allowCORS wraps the given http.Handler with a function that adds the
// Access-Control-Allow-Origin header to the response.
func allowCORS(handler http.Handler, origins []string) http.Handler {
	allowHeaders := "Access-Control-Allow-Headers"
	allowMethods := "Access-Control-Allow-Methods"
	allowOrigin := "Access-Control-Allow-Origin"

	// If the user didn't supply any origins that means CORS is disabled
	// and we should return the original handler.
	if len(origins) == 0 {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Skip everything if the browser doesn't send the Origin field.
		if origin == "" {
			handler.ServeHTTP(w, r)
			return
		}

		// Set the static header fields first.
		// Both a canonicalized and non-canonicalized "grpc-metadata-macaroon" value are
		// set to allow browsers which perform preflight requests and also don't canonicalize
		// the HTTP headers they send (*cough cough CHROME*).
		w.Header()[allowHeaders] = []string{"Content-Type, Accept, Grpc-Metadata-Macaroon, Grpc-Metadata-macaroon"}

		w.Header().Set(allowMethods, "GET, POST, DELETE")

		// Either we allow all origins or the incoming request matches
		// a specific origin in our list of allowed origins.
		for _, allowedOrigin := range origins {
			if allowedOrigin == "*" || origin == allowedOrigin {
				// Only set allowed origin to requested origin.
				w.Header().Set(allowOrigin, origin)

				break
			}
		}

		// For a pre-flight request we only need to send the headers
		// back. No need to call the rest of the chain.
		if r.Method == "OPTIONS" {
			return
		}

		// Everything's prepared now, we can pass the request along the
		// chain of handlers.
		handler.ServeHTTP(w, r)
	})
}
