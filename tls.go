package pool

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lightninglabs/pool/certprovider"
	"github.com/lightninglabs/pool/keychain"
	"github.com/lightninglabs/pool/lnencrypt"
	"github.com/lightninglabs/pool/pooltls"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/lnrpc"
	"google.golang.org/grpc/credentials"
)

const (
	// DefaultTLSCertFilename is the default file name for the autogenerated
	// TLS certificate.
	DefaultTLSCertFilename = "tls.cert"

	// DefaultTLSKeyFilename is the default file name for the autogenerated
	// TLS key.
	DefaultTLSKeyFilename = "tls.key"

	defaultSelfSignedOrganization = "pool autogenerated cert"
)

// getTLSConfig generates a new self signed certificate or refreshes an existing
// one if necessary, then returns the full TLS configuration for initializing
// a secure server interface.
func getTLSConfig(cfg *Config, keyRing keychain.KeyRing) (*tls.Config, *credentials.TransportCredentials, error) {
	var (
		keyType          string
		privateKeyPrefix []byte
	)

	keyType = "rsa"
	privateKeyPrefix = []byte("-----BEGIN RSA PRIVATE KEY-----")

	// Let's load our certificate first or create then load if it doesn't
	// yet exist.
	if !lnrpc.FileExists(cfg.TLSCertPath) && !lnrpc.FileExists(cfg.TLSKeyPath) {
		err := generateSelfSignedCert(cfg, keyRing, keyType)
		if err != nil {
			return nil, nil, err
		}
	}

	certBytes, err := ioutil.ReadFile(cfg.TLSCertPath)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := ioutil.ReadFile(cfg.TLSKeyPath)
	if err != nil {
		return nil, nil, err
	}

	// Do a check to see if the TLS private key is encrypted. If it's encrypted,
	// try to decrypt it. If it's in plaintext but should be encrypted,
	// then encrypt it.
	if !bytes.HasPrefix(keyBytes, privateKeyPrefix) {
		// If the private key is encrypted but the user didn't pass
		// --tlsencryptkey we error out. This is because the wallet is not
		// unlocked yet and we don't have access to the keys yet for decrypt.
		if !cfg.TLSEncryptKey {
			return nil, nil, fmt.Errorf("it appears the TLS key is " +
				"encrypted but you didn't pass the --tlsencryptkey flag. " +
				"Please restart poold with the --tlsencryptkey flag or delete " +
				"the TLS files for regeneration")
		}

		reader := bytes.NewReader(keyBytes)

		keyBytes, err = lnencrypt.DecryptPayloadFromReader(reader, keyRing)
		if err != nil {
			return nil, nil, err
		}
	} else if cfg.TLSEncryptKey {
		// If the user requests an encrypted key but the key is in plaintext
		// we encrypt the key before writing to disk.
		keyBuf := bytes.NewBuffer(keyBytes)
		var b bytes.Buffer

		err = lnencrypt.EncryptPayloadToWriter(*keyBuf, &b, keyRing)
		if err != nil {
			return nil, nil, err
		}

		if err = ioutil.WriteFile(cfg.TLSKeyPath, b.Bytes(), 0600); err != nil {
			return nil, nil, err
		}
	}

	certData, parsedCert, err := pooltls.LoadCertBytes(certBytes, keyBytes)
	if err != nil {
		return nil, nil, err
	}

	// We check whether the certifcate we have on disk match the IPs and
	// domains specified by the config. If the extra IPs or domains have
	// changed from when the certificate was created, we will refresh the
	// certificate if auto refresh is active.
	refresh := false
	if cfg.TLSAutoRefresh {
		refresh, err = cert.IsOutdated(
			parsedCert, cfg.TLSExtraIPs,
			cfg.TLSExtraDomains, cfg.TLSDisableAutofill,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	// If the certificate expired or it was outdated, delete it and the TLS
	// key and generate a new pair.
	if time.Now().After(parsedCert.NotAfter) || refresh {
		log.Info("TLS certificate is expired or outdated, " +
			"removing old file then generating a new one")

		err := os.Remove(cfg.TLSCertPath)
		if err != nil {
			return nil, nil, err
		}

		err = os.Remove(cfg.TLSKeyPath)
		if err != nil {
			return nil, nil, err
		}

		err = generateSelfSignedCert(cfg, keyRing, keyType)
		if err != nil {
			return nil, nil, err
		}

		// Reload the certificate data.
		certBytes, err := ioutil.ReadFile(cfg.TLSCertPath)
		if err != nil {
			return nil, nil, err
		}
		keyBytes, err := ioutil.ReadFile(cfg.TLSKeyPath)
		if err != nil {
			return nil, nil, err
		}

		// If key encryption is set, then decrypt the file.
		// We don't need to do a file type check here because GenCertPair
		// has been ran with the same value for cfg.TLSEncryptKey.
		if cfg.TLSEncryptKey {
			reader := bytes.NewReader(keyBytes)
			keyBytes, err = lnencrypt.DecryptPayloadFromReader(reader, keyRing)
			if err != nil {
				return nil, nil, err
			}
		}

		certData, _, err = pooltls.LoadCertBytes(
			certBytes, keyBytes,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	certList := []tls.Certificate{certData}

	tlsCfg := pooltls.TLSConfFromCert(certList)
	restCreds, err := credentials.NewClientTLSFromFile(cfg.TLSCertPath, "")
	if err != nil {
		return nil, nil, err
	}

	return tlsCfg, &restCreds, nil
}

// getEphemeralTLSConfig returns a temporary TLS configuration with the TLS
// key and cert for the gRPC server and credentials and a proxy destination
// for the REST reverse proxy. The key is not written to disk.
func getEphemeralTLSConfig(cfg *Config, keyRing keychain.KeyRing) (*tls.Config, *credentials.TransportCredentials, error) {
	log.Infof("Generating ephemeral TLS certificates...")

	tmpValidity := 24 * time.Hour
	// Append .tmp to the end of the cert for differentiation.
	tmpCertPath := cfg.TLSCertPath + ".tmp"
	var externalSSLCertPath string

	keyType := "ec"
	if cfg.ExternalSSLProvider != "" {
		keyType = "rsa"
		externalSSLCertPath = fmt.Sprintf("%s/%s/tls.cert.tmp", cfg.BaseDir, cfg.ExternalSSLProvider)
	}

	// Pass in blank string for the key path so the
	// function doesn't write them to disk.
	certBytes, keyBytes, err := pooltls.GenCertPair(
		defaultSelfSignedOrganization, tmpCertPath,
		"", cfg.TLSExtraIPs, cfg.TLSExtraDomains,
		cfg.TLSDisableAutofill, tmpValidity, false, keyRing, keyType,
	)
	if err != nil {
		return nil, nil, err
	}

	var externalCertData tls.Certificate
	if cfg.ExternalSSLProvider != "" {
		externalCertData, err = createExternalCert(
			cfg, keyBytes, externalSSLCertPath,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	log.Infof("Done generating ephemeral TLS certificates")

	certData, parsedCert, err := pooltls.LoadCertBytes(
		certBytes, keyBytes,
	)
	if err != nil {
		return nil, nil, err
	}

	certList := []tls.Certificate{certData}
	if cfg.ExternalSSLProvider != "" {
		certList = append(certList, externalCertData)
	}

	tlsCfg := pooltls.TLSConfFromCert(certList)
	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)
	restCreds := credentials.NewClientTLSFromCert(certPool, "")

	return tlsCfg, &restCreds, nil
}

func generateSelfSignedCert(cfg *Config, keyRing keychain.KeyRing, keyType string) error {
	log.Infof("Generating TLS certificates...")
	_, _, err := pooltls.GenCertPair(
		defaultSelfSignedOrganization, cfg.TLSCertPath,
		cfg.TLSKeyPath, cfg.TLSExtraIPs,
		cfg.TLSExtraDomains, cfg.TLSDisableAutofill,
		cert.DefaultAutogenValidity, cfg.TLSEncryptKey,
		keyRing, keyType,
	)
	if err != nil {
		return err
	}
	log.Infof("Done generating TLS certificates")

	return nil
}

// createExternalCert creates an Externally provisioned SSL Certificate
func createExternalCert(cfg *Config, keyBytes []byte, certLocation string) (returnCert tls.Certificate, err error) {
	var certServer *http.Server

	switch cfg.ExternalSSLProvider {
	case "zerossl":
		return createExternalCertZeroSsl(cfg, keyBytes, certLocation, certServer)
	default:
		return returnCert, fmt.Errorf("unknown external certificate provider: %s", cfg.ExternalSSLProvider)
	}
}

func createExternalCertZeroSsl(cfg *Config, keyBytes []byte,
	certLocation string, certServer *http.Server) (returnCert tls.Certificate, err error) {

	csr, err := certprovider.ZeroSSLGenerateCsr(keyBytes, cfg.ExternalSSLDomain)
	if err != nil {
		return returnCert, err
	}

	log.Debugf("created csr for %s", cfg.ExternalSSLDomain)
	externalCert, err := certprovider.ZeroSSLRequestCert(csr, cfg.ExternalSSLDomain)
	if err != nil {
		return returnCert, err
	}

	log.Infof("received cert request with id %s", externalCert.Id)
	domain := externalCert.CommonName
	path := externalCert.Validation.OtherValidation[domain].FileValidationUrlHttp
	path = strings.Replace(path, "http://"+domain, "", -1)

	content := strings.Join(externalCert.Validation.OtherValidation[domain].FileValidationContent[:], "\n")

	go func() {
		addr := fmt.Sprintf(":%v", cfg.ExternalSSLPort)
		http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(content))
		})
		certServer = &http.Server{
			Addr:    addr,
			Handler: http.DefaultServeMux,
		}
		log.Infof("starting certificate validator server at %s",
			addr)
		err := certServer.ListenAndServe()
		if err != nil {
			log.Errorf("there was a problem starting external cert validation server: %v",
				err)
			return
		}
	}()

	err = certprovider.ZeroSSLValidateCert(externalCert)
	if err != nil {
		return returnCert, err
	}

	log.Debug("requested certificate to be validated")
	checkCount := 0
	retries := 0
	for {
		newCert, err := certprovider.ZeroSSLGetCert(externalCert)
		if err != nil {
			return returnCert, err
		}
		status := newCert.Status
		log.Debugf("found certificate in state %s", status)
		if status == "issued" {
			log.Infof("found certificate in state %s", status)
			break
		} else if status == "draft" {
			err = certprovider.ZeroSSLValidateCert(externalCert)
			if err != nil {
				return returnCert, err
			}
		}
		if retries > 3 {
			log.Error("Still can't get a certificate after 3 retries. Failing...")
			return returnCert, fmt.Errorf("timed out trying to create SSL Certificate")
		}
		if checkCount > 15 {
			log.Warn("Timed out waiting for cert. Requesting a new one.")
			externalCert, err = certprovider.ZeroSSLRequestCert(csr, cfg.ExternalSSLDomain)
			if err != nil {
				return returnCert, err
			}
			log.Infof("received cert request with id %s", externalCert.Id)
			retries += 1
			checkCount = 0
		}
		checkCount += 1
		time.Sleep(2 * time.Second)
	}

	certificate, caBundle, err := certprovider.ZeroSSLDownloadCert(externalCert)
	if err != nil {
		return returnCert, err
	}

	externalCertData, err := writeExternalCert(certificate, caBundle, keyBytes, certLocation)
	if err != nil {
		return returnCert, err
	}

	log.Info("shutting down certificate validator server")
	certServer.Close()

	return externalCertData, nil
}

func writeExternalCert(certificate string, caBundle string,
	keyBytes []byte, certLocation string) (returnCert tls.Certificate, err error) {

	externalCertBytes := []byte(certificate + "\n" + caBundle)
	if err = ioutil.WriteFile(certLocation, externalCertBytes, 0644); err != nil {
		return returnCert, err
	}

	log.Infof("successfully wrote external SSL certificate to %s",
		certLocation)

	externalCertData, _, err := pooltls.LoadCertBytes(
		externalCertBytes, keyBytes,
	)

	if err != nil {
		return returnCert, err
	}

	return externalCertData, nil
}
