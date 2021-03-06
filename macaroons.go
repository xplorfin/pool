package pool

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// poolMacaroonLocation is the value we use for the pool macaroons'
	// "Location" field when baking them.
	poolMacaroonLocation = "pool"

	// macDatabaseOpenTimeout is how long we wait for acquiring the lock on
	// the macaroon database before we give up with an error.
	macDatabaseOpenTimeout = time.Second * 5
)

var (
	// RootKeyIDContextKey is the key to get rootKeyID from context.
	RootKeyIDContextKey = contextKey{"rootkeyid"}

	// DefaultRootKeyID is the ID of the default root key. The first is
	// just 0, to emulate the memory storage that comes with bakery.
	DefaultRootKeyID = []byte("0")
)

// contextKey is the type we use to identify values in the context.
type contextKey struct {
	Name string
}

var (
	// RequiredPermissions is a map of all pool RPC methods and their
	// required macaroon permissions to access poold.
	RequiredPermissions = map[string][]bakery.Op{
		"/poolrpc.Trader/Ping": {{
			Entity: "account",
			Action: "read",
		}},
		"/poolrpc.Trader/TlsCertificate": {{
			Entity: "account",
			Action: "read",
		}},
		"/poolrpc.Trader/QuoteAccount": {{
			Entity: "account",
			Action: "read",
		}},
		"/poolrpc.Trader/InitAccount": {{
			Entity: "account",
			Action: "write",
		}},
		"/poolrpc.Trader/ListAccounts": {{
			Entity: "account",
			Action: "read",
		}},
		"/poolrpc.Trader/CloseAccount": {{
			Entity: "account",
			Action: "write",
		}},
		"/poolrpc.Trader/WithdrawAccount": {{
			Entity: "account",
			Action: "write",
		}},
		"/poolrpc.Trader/DepositAccount": {{
			Entity: "account",
			Action: "write",
		}},
		"/poolrpc.Trader/RenewAccount": {{
			Entity: "account",
			Action: "write",
		}},
		"/poolrpc.Trader/BumpAccountFee": {{
			Entity: "account",
			Action: "write",
		}},
		"/poolrpc.Trader/RecoverAccounts": {{
			Entity: "account",
			Action: "write",
		}},
		"/poolrpc.Trader/SubmitOrder": {{
			Entity: "order",
			Action: "write",
		}},
		"/poolrpc.Trader/ListOrders": {{
			Entity: "order",
			Action: "read",
		}},
		"/poolrpc.Trader/CancelOrder": {{
			Entity: "order",
			Action: "write",
		}},
		"/poolrpc.Trader/AuctionFee": {{
			Entity: "auction",
			Action: "read",
		}},
		"/poolrpc.Trader/Leases": {{
			Entity: "auction",
			Action: "read",
		}},
		"/poolrpc.Trader/BatchSnapshot": {{
			Entity: "auction",
			Action: "read",
		}},
		"/poolrpc.Trader/GetLsatTokens": {{
			Entity: "auth",
			Action: "read",
		}},
		"/poolrpc.Trader/LeaseDurations": {{
			Entity: "auction",
			Action: "read",
		}},
		"/poolrpc.Trader/NextBatchInfo": {{
			Entity: "auction",
			Action: "read",
		}},
		"/poolrpc.Trader/NodeRatings": {{
			Entity: "auction",
			Action: "read",
		}},
		"/poolrpc.Trader/BatchSnapshots": {{
			Entity: "auction",
			Action: "read",
		}},
	}

	// allPermissions is the list of all existing permissions that exist
	// for poold's RPC. The default macaroon that is created on startup
	// contains all these permissions and is therefore equivalent to lnd's
	// admin.macaroon but for pool.
	allPermissions = []bakery.Op{{
		Entity: "account",
		Action: "read",
	}, {
		Entity: "account",
		Action: "write",
	}, {
		Entity: "order",
		Action: "read",
	}, {
		Entity: "order",
		Action: "write",
	}, {
		Entity: "auction",
		Action: "read",
	}, {
		Entity: "auth",
		Action: "read",
	}}

	// macDbDefaultPw is the default encryption password used to encrypt the
	// pool macaroon database. The macaroon service requires us to set a
	// non-nil password so we set it to an empty string. This will cause the
	// keys to be encrypted on disk but won't provide any security at all as
	// the password is known to anyone.
	//
	// TODO(guggero): Allow the password to be specified by the user. Needs
	// create/unlock calls in the RPC. Using a password should be optional
	// though.
	macDbDefaultPw = []byte("ello")
)

// startMacaroonService starts the macaroon validation service, creates or
// unlocks the macaroon database and creates the default macaroon if it doesn't
// exist yet. If macaroons are disabled in general in the configuration, none of
// these actions are taken.
// If statelessInit is true, returns the raw byte data of the generated
// macaroon and does not write it to disk. Otherwise, the raw macaroon data
// is not returned, and the macaroon is written to disk.
func (s *Server) startMacaroonService(statelessInit bool) ([]byte, error) {
	var (
		err          error
		poolMacBytes []byte
	)

	// Create the macaroon authentication/authorization service.
	s.macaroonService, err = macaroons.NewService(
		s.cfg.BaseDir, poolMacaroonLocation, statelessInit,
		macDatabaseOpenTimeout, macaroons.IPLockChecker,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to set up macaroon authentication: "+
			"%v", err)
	}

	// Try to unlock the macaroon store with the private password.
	err = s.macaroonService.CreateUnlock(&macDbDefaultPw)
	if err != nil {
		return nil, fmt.Errorf("unable to unlock macaroon DB: %v", err)
	}

	poolMacBytes, err = s.bakeMacaroon()
	if err != nil {
		return nil, fmt.Errorf("unable to bake macaroon: %v", err)
	}

	if statelessInit {
		return poolMacBytes, nil
	}

	return poolMacBytes, writeMacaroon(s.cfg.MacaroonPath, poolMacBytes)
}

// Bakes a macaroon.
// Yum.
func (s *Server) bakeMacaroon() ([]byte, error) {
	ctx := context.Background()
	ctx = ContextWithRootKeyID(ctx, DefaultRootKeyID)

	// We only generate one default macaroon that contains all
	// existing permissions (equivalent to the admin.macaroon in
	// lnd). Custom macaroons can be created through the bakery
	// RPC.
	poolMac, err := s.macaroonService.NewMacaroon(
		ctx, DefaultRootKeyID, allPermissions...,
	)
	if err != nil {
		return nil, err
	}

	return poolMac.M().MarshalBinary()
}

// Create macaroon files for pool CLI to use if they don't exist.
func writeMacaroon(macaroonPath string, poolMacBytes []byte) error {
	if !lnrpc.FileExists(macaroonPath) {
		err := ioutil.WriteFile(macaroonPath, poolMacBytes, 0644)
		if err != nil {
			if err := os.Remove(macaroonPath); err != nil {
				log.Errorf("Unable to remove %s: %v",
					macaroonPath, err)
			}

			return err
		}
	}

	return nil
}

// stopMacaroonService closes the macaroon database.
func (s *Server) stopMacaroonService() error {
	return s.macaroonService.Close()
}

// macaroonInterceptor creates macaroon security interceptors.
func (s *Server) macaroonInterceptor() (grpc.UnaryServerInterceptor,
	grpc.StreamServerInterceptor) {

	unaryInterceptor := s.macaroonService.UnaryServerInterceptor(
		RequiredPermissions,
	)
	streamInterceptor := s.macaroonService.StreamServerInterceptor(
		RequiredPermissions,
	)
	return unaryInterceptor, streamInterceptor
}

// ContextWithRootKeyID passes the root key ID value to context.
func ContextWithRootKeyID(ctx context.Context,
	value interface{}) context.Context {

	return context.WithValue(ctx, RootKeyIDContextKey, value)
}
