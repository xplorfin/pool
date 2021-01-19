package pooltls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/lightninglabs/pool/keychain"
	"github.com/lightninglabs/pool/lnencrypt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	// DefaultAutogenValidity is the default validity of a self-signed
	// certificate. The value corresponds to 14 months
	// (14 months * 30 days * 24 hours).
	DefaultAutogenValidity = 14 * 30 * 24 * time.Hour
)

var (
	// End of ASN.1 time.
	endOfTime = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)

	// Max serial number.
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
)

// ipAddresses returns the parserd IP addresses to use when creating the TLS
// certificate. If tlsDisableAutofill is true, we don't include interface
// addresses to protect users privacy.
func ipAddresses(tlsExtraIPs []string, tlsDisableAutofill bool) ([]net.IP, error) {
	// Collect the host's IP addresses, including loopback, in a slice.
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	// addIP appends an IP address only if it isn't already in the slice.
	addIP := func(ipAddr net.IP) {
		for _, ip := range ipAddresses {
			if ip.Equal(ipAddr) {
				return
			}
		}
		ipAddresses = append(ipAddresses, ipAddr)
	}

	// To protect their privacy, some users might not want to have all
	// their network addresses include in the certificate as this could
	// leak sensitive information.
	if !tlsDisableAutofill {
		// Add all the interface IPs that aren't already in the slice.
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ipAddr, _, err := net.ParseCIDR(a.String())
			if err == nil {
				addIP(ipAddr)
			}
		}
	}

	// Add extra IPs to the slice.
	for _, ip := range tlsExtraIPs {
		ipAddr := net.ParseIP(ip)
		if ipAddr != nil {
			addIP(ipAddr)
		}
	}

	return ipAddresses, nil
}

// dnsNames returns the host and DNS names to use when creating the TLS
// ceftificate.
func dnsNames(tlsExtraDomains []string, tlsDisableAutofill bool) (string, []string) {
	// Collect the host's names into a slice.
	host, err := os.Hostname()

	// To further protect their privacy, some users might not want
	// to have their hostname include in the certificate as this could
	// leak sensitive information.
	if err != nil || tlsDisableAutofill {
		// Nothing much we can do here, other than falling back to
		// localhost as fallback. A hostname can still be provided with
		// the tlsExtraDomain parameter if the problem persists on a
		// system.
		host = "localhost"
	}

	dnsNames := []string{host}
	if host != "localhost" {
		dnsNames = append(dnsNames, "localhost")
	}
	dnsNames = append(dnsNames, tlsExtraDomains...)

	// Because we aren't including the hostname in the certificate when
	// tlsDisableAutofill is set, we will use the first extra domain
	// specified by the user, if it's set, as the Common Name.
	if tlsDisableAutofill && len(tlsExtraDomains) > 0 {
		host = tlsExtraDomains[0]
	}

	// Also add fake hostnames for unix sockets, otherwise hostname
	// verification will fail in the client.
	dnsNames = append(dnsNames, "unix", "unixpacket")

	// Also add hostnames for 'bufconn' which is the hostname used for the
	// in-memory connections used on mobile.
	dnsNames = append(dnsNames, "bufconn")

	return host, dnsNames
}

// GenCertPair generates a key/cert pair to the paths provided if defined.
// The bytes of the generated certificate and private key are returned.
//
// The auto-generated certificates should *not* be used in production for public
// access as they're self-signed and don't necessarily contain all of the
// desired hostnames for the service. For production/public use, consider a
// real PKI.
//
// This function is adapted from https://github.com/btcsuite/btcd and
// https://github.com/btcsuite/btcutil
func GenCertPair(org, certFile, keyFile string, tlsExtraIPs,
	tlsExtraDomains []string, tlsDisableAutofill bool,
	certValidity time.Duration, encryptKey bool,
	keyRing keychain.KeyRing, keyType string) ([]byte, []byte, error) {

	now := time.Now()
	validUntil := now.Add(certValidity)

	// Check that the certificate validity isn't past the ASN.1 end of time.
	if validUntil.After(endOfTime) {
		validUntil = endOfTime
	}

	// Generate a serial number that's below the serialNumberLimit.
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	// Get all DNS names and IP addresses to use when creating the
	// certificate.
	host, dnsNames := dnsNames(tlsExtraDomains, tlsDisableAutofill)
	ipAddresses, err := ipAddresses(tlsExtraIPs, tlsDisableAutofill)
	if err != nil {
		return nil, nil, err
	}

	// Construct the certificate template.
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   host,
		},
		NotBefore: now.Add(-time.Hour * 24),
		NotAfter:  validUntil,

		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true, // so can sign self.
		BasicConstraintsValid: true,

		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}

	// Generate a private key for the certificate.
	var derBytes []byte
	var keyBytes []byte
	var encodeString string

	if keyType == "ec" {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		derBytes, err = x509.CreateCertificate(rand.Reader, &template,
			&template, &priv.PublicKey, priv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
		}

		keyBytes, err = x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to encode privkey: %v", err)
		}
		encodeString = "EC PRIVATE KEY"
	} else if keyType == "rsa" {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}

		derBytes, err = x509.CreateCertificate(rand.Reader, &template,
			&template, &priv.PublicKey, priv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
		}

		keyBytes = x509.MarshalPKCS1PrivateKey(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to encode privkey: %v", err)
		}
		encodeString = "RSA PRIVATE KEY"
	} else {
		return nil, nil, fmt.Errorf("Unknown keyType: %s", keyType)
	}

	certBuf := &bytes.Buffer{}

	err = pem.Encode(certBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode certificate: %v", err)
	}

	keyBuf := &bytes.Buffer{}

	err = pem.Encode(keyBuf, &pem.Block{
		Type:  encodeString,
		Bytes: keyBytes})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode private key: %v", err)
	}

	// Write cert and key files. Ensures the paths are defined before writing.
	if certFile != "" {
		if err = ioutil.WriteFile(certFile, certBuf.Bytes(), 0644); err != nil {
			return nil, nil, err
		}
	}

	if keyFile != "" {
		keyPayload := keyBuf.Bytes()
		// If the user requests the TLS key to be encrypted on disk we do so
		if encryptKey {
			var b bytes.Buffer

			err = lnencrypt.EncryptPayloadToWriter(*keyBuf, &b, keyRing)
			if err != nil {
				return nil, nil, err
			}

			keyPayload = b.Bytes()
		}
		if err = ioutil.WriteFile(keyFile, keyPayload, 0600); err != nil {
			os.Remove(certFile)
			return nil, nil, err
		}
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}
