/*
 * Copyright (c) 2020 Aaron Blair
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of the project's author nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* Go Config inspired by:
 * https://github.com/koddr/example-go-config-yaml/blob/master/LICENSE
 * https://dev.to/ilyakaznacheev/a-clean-way-to-pass-configs-in-a-go-application-1g64
 * https://dev.to/koddr/let-s-write-config-for-your-golang-web-app-on-right-way-yaml-5ggp */

package hsmocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"github.com/hashicorp/vault/api"
	"github.com/kelseyhightower/envconfig"
	vault_ocsp "github.com/spyd3rweb/vault-ocsp"
	"golang.org/x/crypto/ocsp"
	yaml "gopkg.in/yaml.v2"
)

var levelPrefix = [...]string{
	log.LevelDebug:    "DEBUG",
	log.LevelInfo:     "INFO",
	log.LevelWarning:  "WARNING",
	log.LevelError:    "ERROR",
	log.LevelCritical: "CRITICAL",
	log.LevelFatal:    "FATAL",
}

// KeyHsmConfig is used to configure a PKCS11 cryptoSigner
type KeyHsmConfig struct {
	// ModulePath is path to PKCS#11 library.
	ModulePath string `yaml:"modulePath"`
	// SlotNumber identifies a token to use by the slot containing it.
	// negative value defaults to Token label
	SlotNumber int `yaml:"slotNumber"`
	// TokenLabel, used to identify the Token, which is prefered over SlotID
	TokenLabel string `yaml:"tokenLabel"`
	// KeyLabel, used to identify the KeyPair, which is prefered over the KeyID
	KeyLabel string `yaml:"keyLabel"`
	// KeyID, hex id used to identify the KeyPair, though not required to find if label is provided
	// KeyPairs must have a NON-EMPTY CKA_ID to be found
	KeyID string `yaml:"keyID"`
	// HSM Pin
	Pin string `required:"true" envconfig:"HSM_PIN" yaml:"pin"`
}

// OcspSourceHandleConfig are the certs and keys required to sign OCSP responses
type OcspSourceHandleConfig struct {
	// Pattern is the pattern for the router handle
	OcspPattern string `yaml:"pattern"`
	// OscpCertPath is a required Uri (file path or http url)
	OcspCertPath string `yaml:"certPath"`
	// OcspKeyPath is the optional Uri (file path)
	OcspKeyPath string `yaml:"keyPath"`
	// OcspKeyHsm is used to configure a PKCS11 cryptoSigner
	// If OcspKeyPath is set to ''
	OcspKeyHsm KeyHsmConfig `yaml:"keyHsm"`
}

// CaSourceHandleConfig are the OpenSSL CA certs, crls, and index
type CaSourceHandleConfig struct {
	// CaCertPattern is pattern for the router handle
	CaCertPattern string `yaml:"certPattern"`
	// CaCertPath is a required Uri (file path or http url)
	CaCertPath string `yaml:"certPath"`
	// CaCrlPattern pattern for the router handle
	CaCrlPattern string `yaml:"crlPattern"`
	// CaCrlPath is a required Uri (file path or http url)
	CaCrlPath string `yaml:"crlPath"`
	// CaIncexPath is a required Uri (file path or http url)
	CaIndexPath string `yaml:"indexPath"`
}

// ReadinessProbeHandleConfig configures the handle for the Readiness Probe
type ReadinessProbeHandleConfig struct {
	Pattern string `yaml:"pattern"`
}

// LivenessProbeHandleConfig configures the handle for the Liveness Probe
type LivenessProbeHandleConfig struct {
	Pattern string `yaml:"pattern"`
}

// OpenSslSourceHandleConfig configures the OCSP Sources for the ocsp responder
type OpenSslSourceHandleConfig struct {
	OcspSourceHandle     OcspSourceHandleConfig `yaml:"ocsp"`
	CaSourceHandleConfig `yaml:"ca"`
}

// VaultConfig configures the OCSP Sources for the ocsp responder
type VaultConfig struct {
	// VaultMount is the pki mount for your ocsp (assumes ca, crl, and cert vault urls)
	PkiMount string     `yaml:"pkiMount"`
	Client   api.Config `yaml:"api"`
}

// VaultSourceHandleConfig Source config for the ocsp responder http server(s)
type VaultSourceHandleConfig struct {
	OcspSourceHandle OcspSourceHandleConfig `yaml:"ocsp"`
	VaultConfig      `yaml:"vault"`
}

// Config struct for hsm ocsp server
type Config struct {
	// LogLevel
	LogLevel int `yaml:"logLevel"`
	Server   struct {
		// Host is the local machine IP Address to bind the HTTP Server to
		Host string `yaml:"host"`
		// Port is the local machine TCP Port to bind the HTTP Server to
		Port string `yaml:"port"`
		// Time out
		Timeout struct {
			// Server is the general server timeout to use
			// for graceful shutdowns
			Server time.Duration `yaml:"server"`
			// Write is the amount of time to wait until an HTTP server
			// write opperation is cancelled
			Write time.Duration `yaml:"write"`
			// Read is the amount of time to wait until an HTTP server
			// read operation is cancelled
			Read time.Duration `yaml:"read"`
			// Idle is the amount of time to wait
			// until an IDLE HTTP session is closed
			Idle time.Duration `yaml:"idle"`
		} `yaml:"timeout"`
		// ReadinessProbeHandles configures the handle for readiness probe
		ReadinessProbeHandle ReadinessProbeHandleConfig `yaml:"readinessProbeHandle"`
		// LivenessProbeHandles configures the handle for liveness probe
		LivenessProbeHandle LivenessProbeHandleConfig `yaml:"livenessProbeHandle"`
		// OpenSslSourceHandles configures Source and Handles for ocsp responder
		OpenSslSourceHandles []OpenSslSourceHandleConfig `yaml:"opensslSourceHandles,flow"`
		// VaultSourceHandles configures Source and Handles for ocsp responder
		VaultSourceHandles []VaultSourceHandleConfig `yaml:"vaultSourceHandles,flow"`
	} `yaml:"server"`
}

// CertStatus are the possible values for Cert Status from the openssl ca database flat file
type CertStatus string

const (
	valid   CertStatus = "V"
	revoked CertStatus = "R"
	expired CertStatus = "E"
	unknown CertStatus = ""
)

// OpenSslIndexRecord for records from the openssl ca database flat file
type OpenSslIndexRecord struct {
	status            CertStatus
	expirationTime    time.Time
	revocationTime    time.Time
	serial            string
	fileName          string
	distinguishedName string
}

// OpenSslSource Source struct for ocsp responder
type OpenSslSource struct {
	cached     map[string][]byte
	certIndex  map[string]*OpenSslIndexRecord
	crlLock    *sync.Mutex
	caCrl      *pkix.CertificateList
	caCert     *x509.Certificate
	ocspCert   *x509.Certificate
	ocspSigner *crypto.Signer
}

// processError processes errors and exits
func processError(msgfmt string, err error) {
	log.Criticalf(msgfmt, err)
	os.Exit(2)
}

// NewConfig returns a new decoded Config struct
func NewConfig(configPath string) (*Config, error) {
	// create config structure
	config := &Config{}

	// Fetch file data
	data, err := fetchFile(configPath)
	if err != nil {
		return nil, err
	}

	// Start YAML unmarshaling/decoding from byte data
	yaml.Unmarshal(data, &config)

	return config, nil
}

// fetchFile fetches a local file URI and returns the data as bytes
func fetchFile(uri string) ([]byte, error) {
	s, err := os.Stat(uri)
	if err != nil {
		return nil, err
	}
	if s.IsDir() {
		return nil, fmt.Errorf("'%s' is a directory, not a normal file", uri)
	}

	// Open config file
	file, err := os.Open(uri)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	file.Close()

	return data, nil
}

func fetchURL(uri string) ([]byte, error) {
	// Parse http uri
	_, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, err
	}

	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve URL")
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return data, nil
}

// fetchData fetches a URI and returns the data as bytes
func fetchURI(uri string) ([]byte, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "file" || u.Scheme == "" || u.Host == "" {
		// file
		return fetchFile(uri)
	}

	// http
	return fetchURL(uri)
}

// fetchCRL fetches and parses a CRL.
// https://github.com/cloudflare/cfssl/blob/master/revoke/revoke.go
func fetchCRL(uri string) (*pkix.CertificateList, error) {
	data, err := fetchURI(uri)
	if err != nil {
		return nil, err
	}
	return x509.ParseCRL(data)
}

// fetchCRL fetches and parses a certificate.
func fetchCert(uri string) (*x509.Certificate, error) {
	data, err := fetchURI(uri)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock != nil {
		return helpers.ParseCertificatePEM(data)
	}

	return x509.ParseCertificate(data)
}

// fetcCerthKeySigner fetches an RSA based key and returns a crypto.Signer
func fetchCertKeySigner(uri string) (crypto.Signer, error) {
	data, err := fetchURI(uri)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock != nil {
		return helpers.ParsePrivateKeyPEM(data)
	}

	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

// fetchHsmKeySigner fetches an HSM based key and returns a crypto.Signer
func fetchHsmKeySigner(keyHsm KeyHsmConfig) (crypto.Signer, error) {

	var slotNumber *int = nil
	// prefer token label over slot id
	if keyHsm.TokenLabel == "" && keyHsm.SlotNumber > 0 {
		slotNumber = &keyHsm.SlotNumber
	}

	// ensure pin is set
	if keyHsm.Pin == "" {
		// Retrieve pin config
		if err := envconfig.Process("", &keyHsm); err != nil {
			return nil, err
		}
	}

	crypto11Config := &crypto11.Config{
		Path:       keyHsm.ModulePath,
		SlotNumber: slotNumber,
		TokenLabel: keyHsm.TokenLabel,
		Pin:        keyHsm.Pin,
	}

	crypto11Context, err := crypto11.Configure(crypto11Config)
	if err != nil {
		return nil, err
	}

	var keySigner crypto11.Signer
	var findErrMsg string
	var findErr error
	// Use one EITHER Key ID OR Label
	if (keyHsm.KeyLabel == "" && keyHsm.KeyID == "") || (keyHsm.KeyLabel != "" && keyHsm.KeyID != "") {
		return nil, fmt.Errorf("One, and only one, of EITHER KeyID OR KeyLabel must be specified")
	} else if keyHsm.KeyLabel != "" {
		findErrMsg = fmt.Sprintf("KeyPair could not be located with KeyLabel: '%s'", keyHsm.KeyLabel)
		keySigner, findErr = crypto11Context.FindKeyPair(nil, []byte(keyHsm.KeyLabel))

	} else if keyHsm.KeyID != "" {
		findErrMsg = fmt.Sprintf("KeyPair could not be located with KeyID: '%s'", keyHsm.KeyID)
		keySigner, findErr = crypto11Context.FindKeyPair([]byte(keyHsm.KeyID), nil)
	}

	if err != nil {
		return nil, err
	} else if keySigner == nil {
		return nil, fmt.Errorf("%s'\nKeyPairs must have a NON-EMPTY CKA_ID to be found: %v", findErrMsg, findErr)
	}

	return keySigner, nil
}

// fetchKey fetches and RSA key and returns a crypto.Signer
func fetchKeySigner(handleConfig OcspSourceHandleConfig) (crypto.Signer, error) {
	var ocspSigner crypto.Signer
	var err error
	if handleConfig.OcspKeyPath != "" {
		log.Debugf("fetching key uri '%s'", handleConfig.OcspKeyPath)
		ocspSigner, err = fetchCertKeySigner(handleConfig.OcspKeyPath)
		if err != nil {
			return nil, fmt.Errorf("Error, invalid responder key: %v", err)
		}
	} else {
		// PKCS11 HSM
		log.Debugf("fetching hsm key, PKCS#11 (slot-id: '%d', token-label: '%s', key-label: '%s')",
			handleConfig.OcspKeyHsm.SlotNumber, handleConfig.OcspKeyHsm.TokenLabel, handleConfig.OcspKeyHsm.KeyLabel)
		ocspSigner, err = fetchHsmKeySigner(handleConfig.OcspKeyHsm)
		if err != nil {
			return nil, fmt.Errorf("Error, invalid hsm key: %v", err)
		}
	}

	return ocspSigner, nil
}

func getCertStatusFromString(str string) (CertStatus, error) {
	switch str {
	case fmt.Sprintf("%s", valid):
		return valid, nil
	case fmt.Sprintf("%s", expired):
		return expired, nil
	case fmt.Sprintf("%s", revoked):
		return revoked, nil
	default:
		return unknown, fmt.Errorf("Unknown cert type %s", str)
	}
}

func getTimeFromAsn1String(str string) (*time.Time, error) {
	// YYMMDDHHMMSSZ
	utcRegex := regexp.MustCompile(`^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$`)
	utcMatches := utcRegex.FindAllStringSubmatch(str, -1)
	if len(utcMatches) > 0 {
		utcMatch := utcMatches[0][1:]
		year, err := strconv.Atoi(utcMatch[0])
		if err != nil {
			return nil, err
		}
		// UTC can only support until 2050, if YY is < 50 the century is 2000 else 1900
		if year < 50 {
			year += 2000
		} else {
			year += 1900
		}
		month, err := strconv.Atoi(utcMatch[1])
		if err != nil {
			return nil, err
		}
		day, err := strconv.Atoi(utcMatch[2])
		if err != nil {
			return nil, err
		}
		hour, err := strconv.Atoi(utcMatch[3])
		if err != nil {
			return nil, err
		}
		min, err := strconv.Atoi(utcMatch[4])
		if err != nil {
			return nil, err
		}
		sec, err := strconv.Atoi(utcMatch[5])
		if err != nil {
			return nil, err
		}

		t := time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC)

		return &t, nil
	}

	return nil, fmt.Errorf("Unexpected date format [%s]; expected [YYMMDDHHMMSSZ]", str)
}

// ParseOpenSslIndexRecord creates a new struct from csv record
func ParseOpenSslIndexRecord(record []string) (*OpenSslIndexRecord, error) {

	recordLen := len(record)
	if recordLen != 6 {
		return nil, fmt.Errorf("record length of [%d] is unexpected for a ca db index file; expected [6]", recordLen)
	}
	// Cert status
	status, err := getCertStatusFromString(record[0])
	if err != nil {
		return nil, err
	}
	// Cert Expiration Time
	expirationTime, err := getTimeFromAsn1String(record[1])
	if err != nil {
		return nil, err
	}

	// Cert Revocation time
	var revocationTime *time.Time = nil
	// only revoked certificates have revocationTimes
	if status == revoked || record[2] != "" {
		revocationTime, err = getTimeFromAsn1String(record[2])
		if err != nil {
			return nil, err
		}
	} else {
		revocationTime = &time.Time{}
	}

	// Cert Cerial number
	serial := record[3]
	// Cert Filename
	fileName := record[4]
	// Cert Distinguished name
	distinguishedName := record[5]

	certRecord := &OpenSslIndexRecord{
		status:            status,
		expirationTime:    *expirationTime,
		revocationTime:    *revocationTime,
		serial:            serial,
		fileName:          fileName,
		distinguishedName: distinguishedName,
	}

	return certRecord, nil
}

// ParseOpenSslIndex parses csv byte data from an openssl ca database flat file
// https://pki-tutorial.readthedocs.io/en/latest/cadb.html
func ParseOpenSslIndex(data []byte) (map[string]*OpenSslIndexRecord, error) {
	certIndex := make(map[string]*OpenSslIndexRecord)
	recordRegex := regexp.MustCompile(`(?m)^([VRE])\s+(\d{1,}Z)\s+(\d{1,}Z)?\s+([A-F0-9]+)\s+(.*?)\s+(\/.+)$`)
	records := recordRegex.FindAllStringSubmatch(string(data), -1)
	// Iterate through the ca db records
	for _, record := range records {
		certRecord, err := ParseOpenSslIndexRecord(record[1:])
		if err != nil {
			return nil, err
		}

		i := new(big.Int)
		i.SetString(certRecord.serial, 16)
		cachekey := i.String()
		certIndex[cachekey] = certRecord
	}

	return certIndex, nil
}

// fetchOpenSslIndex fetches an OpenSSL database index flat file and adds entries to cache
// https://pki-tutorial.readthedocs.io/en/latest/cadb.html
func fetchOpenSslIndex(uri string) (map[string]*OpenSslIndexRecord, error) {
	data, err := fetchURI(uri)
	if err != nil {
		return nil, err
	}

	return ParseOpenSslIndex(data)
}

// NewOpenSslSource creates a Source for OCSP server responder
func NewOpenSslSource(certIndex map[string]*OpenSslIndexRecord, caCrl *pkix.CertificateList, caCert *x509.Certificate, ocspCert *x509.Certificate, ocspSigner *crypto.Signer) (*OpenSslSource, error) {

	openSslSource := &OpenSslSource{
		cached:     make(map[string][]byte),
		crlLock:    &sync.Mutex{},
		certIndex:  certIndex,
		caCrl:      caCrl,
		caCert:     caCert,
		ocspCert:   ocspCert,
		ocspSigner: ocspSigner,
	}
	return openSslSource, nil
}

// NewOpenSslSourceFromHandleConfig creates OpenSslSources and adds the handle for the Ocsp Responder
func NewOpenSslSourceFromHandleConfig(handleConfig OpenSslSourceHandleConfig) (*OpenSslSource, error) {
	log.Debugf("fetching ca certificate uri '%s'", handleConfig.CaCertPath)
	caCert, err := fetchCert(handleConfig.CaCertPath)
	if err != nil {
		processError("Error, invalid ca certificate: %v", err)
	}

	log.Debugf("fetching ca crl uri '%s'", handleConfig.CaCrlPath)
	caCrl, err := fetchCRL(handleConfig.CaCrlPath)
	if err != nil {
		processError("Error, invalid ca crl: %v", err)
	}

	log.Debugf("fetching ca index uri '%s'", handleConfig.CaIndexPath)
	caIndex, err := fetchOpenSslIndex(handleConfig.CaIndexPath)
	if err != nil {
		processError("Error, invalid ca index: %v", err)
	}

	log.Debugf("fetching ocsp responder certificate uri '%s'", handleConfig.OcspSourceHandle.OcspCertPath)
	ocspCert, err := fetchCert(handleConfig.OcspSourceHandle.OcspCertPath)
	if err != nil {
		processError("Error, invalid ocsp responder certificate: %v", err)
	}

	ocspSigner, err := fetchKeySigner(handleConfig.OcspSourceHandle)
	if err != nil {
		processError("Error, invalid ocsp responder key: %v", err)
	}

	return NewOpenSslSource(caIndex, caCrl, caCert, ocspCert, &ocspSigner)
}

// NewVaultSourceFromHandleConfig creates VaultSources and adds the handle for the Ocsp Responder
func NewVaultSourceFromHandleConfig(handleConfig *VaultSourceHandleConfig) (*vault_ocsp.VaultSource, error) {
	log.Debugf("fetching ocsp responder certificate uri '%s'", handleConfig.OcspSourceHandle.OcspCertPath)
	ocspCert, err := fetchCert(handleConfig.OcspSourceHandle.OcspCertPath)
	if err != nil {
		processError("Error, invalid ocsp responder certificate: %v", err)
	}

	ocspSigner, err := fetchKeySigner(handleConfig.OcspSourceHandle)
	if err != nil {
		processError("Error, invalid ocsp responder key: %v", err)
	}

	return vault_ocsp.NewVaultSource(handleConfig.PkiMount, ocspCert, &ocspSigner, &handleConfig.Client)
}

func validateUniqueHandlePattern(pattern string, set map[string]error) (*url.URL, error) {
	if err, exists := set[pattern]; exists {
		return nil, err
	}
	// set for next use
	set[pattern] = fmt.Errorf("Handle '%s' has already been configured", pattern)
	return url.Parse("/" + pattern)
}

// readyz is a readiness probe.
func readyz(isReady *atomic.Value) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if isReady == nil || !isReady.Load().(bool) {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// NewRouter generates the router used in the HTTP Server
func NewRouter(config Config) *http.ServeMux {
	// Create router
	router := http.NewServeMux()
	set := make(map[string]error)

	// liveness probe handle
	livenessURL, err := validateUniqueHandlePattern(config.Server.LivenessProbeHandle.Pattern, set)
	if err != nil {
		processError("liveness probe url pattern failed: %v", err)
	}
	log.Infof("Configuring App Handle with liveness probe url pattern '%s'", livenessURL.String())
	router.HandleFunc(livenessURL.String(), func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Received HTTP Request for App Handle with liveness probe url pattern '%s'", livenessURL.String())
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	// Iterate through OpenSSL Handles routes from config
	for i, handleConfig := range config.Server.OpenSslSourceHandles {
		log.Infof("Initializing OpenSSL Source [%d] from config", i)
		// Define handles for OpenSSL OCSP Respodner
		openSslSource, err := NewOpenSslSourceFromHandleConfig(handleConfig)
		if err != nil {
			processError("OpenSSL Source initialization failed: %v", err)
		}

		if handleConfig.CaCertPattern != "" {
			// ca cert handle
			caCertURL, err := validateUniqueHandlePattern(handleConfig.CaCertPattern, set)
			if err != nil {
				processError("ca cert url pattern validation failed: %v", err)
			}
			log.Infof("Configuring OpenSSL Source [%d] Handle with ca cert url pattern '%s'", i, caCertURL.String())
			router.HandleFunc(caCertURL.String(), func(w http.ResponseWriter, r *http.Request) {
				log.Debugf("Received HTTP Request for OpenSSL Source [%d] Handle with ca cert url pattern '%s'", i, caCertURL.String())
				http.ServeFile(w, r, handleConfig.CaCertPath)
			})
		}

		if handleConfig.CaCrlPattern != "" {
			// ca crl handle
			caCrlURL, err := validateUniqueHandlePattern(handleConfig.CaCrlPattern, set)
			if err != nil {
				processError("ca crl url pattern validation failed: %v", err)
			}
			log.Infof("Configuring OpenSSL Source [%d] Handle with ca crl url pattern '%s'", i, caCrlURL.String())
			router.HandleFunc(caCrlURL.String(), func(w http.ResponseWriter, r *http.Request) {
				log.Debugf("Received HTTP Request for OpenSSL Source [%d] Handle with ca crl url pattern '%s'", i, caCrlURL.String())
				http.ServeFile(w, r, handleConfig.CaCrlPath)
			})
		}

		// ocsp Handle
		ocspURL, err := validateUniqueHandlePattern(handleConfig.OcspSourceHandle.OcspPattern, set)
		if err != nil {
			processError("ocsp url pattern validation failed: %v", err)
		}
		log.Infof("Configuring OpenSSL Source [%d] Handle with ocsp url pattern '%s'", i, ocspURL.String())
		router.Handle(ocspURL.String(), cfocsp.NewResponder(openSslSource, nil))
	}

	// Iterate through Vault Handles routes from config
	for i := range config.Server.VaultSourceHandles {
		// api contains lock, so must use reference (range is by value)
		handleConfig := &(config.Server.VaultSourceHandles[i])
		log.Infof("Initializing Vault Source [%d] from config", i)
		// Define handles for Vault OCSP Responder
		vaultSource, err := NewVaultSourceFromHandleConfig(handleConfig)
		if err != nil {
			processError("Vault Source initialization failed: %v", err)
		}
		// ocsp handle
		ocspURL, err := validateUniqueHandlePattern(handleConfig.OcspSourceHandle.OcspPattern, set)
		if err != nil {
			processError("ocsp url pattern validation failed: %v", err)
		}
		log.Infof("Configuring Vault Source [%d] Handle with ocsp url pattern '%s'", i, ocspURL.String())
		router.Handle(ocspURL.String(), cfocsp.NewResponder(vaultSource, nil))
	}

	// readiness probe handle
	readinessURL, err := validateUniqueHandlePattern(config.Server.ReadinessProbeHandle.Pattern, set)
	if err != nil {
		processError("readiness probe url pattern validation failed: %v", err)
	}
	log.Infof("Configuring App Handle with readiness probe url pattern '%s'", readinessURL.String())
	router.HandleFunc(readinessURL.String(), func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Received HTTP Request for App Handle with readiness probe url pattern '%s'", readinessURL.String())
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	// Return the router
	return router
}

// Run will run the HTTP Server
func (config Config) Run() {
	// Set Log Level
	defaultLogLevel := 0
	if config.LogLevel < 0 || config.LogLevel >= len(levelPrefix) {
		log.Warningf("Log Level is invalid [%d], expecting:\n", config.LogLevel)
		for i, level := range levelPrefix {
			log.Warningf("[%d]: %+v", i, level)
		}
		config.LogLevel = defaultLogLevel
	}

	log.Infof("Setting Log Level to [%d]: %s\n", config.LogLevel, levelPrefix[config.LogLevel])
	log.Level = defaultLogLevel

	// Setup a channel to list to for interuppt signals
	var runChan = make(chan os.Signal, 1)

	// Setup a context to allow for graceful server shutdowns in the event
	// of an OS interrupt (defers the cancel just in case)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		config.Server.Timeout.Server,
	)
	defer cancel()

	// Define server options:
	server := &http.Server{
		Addr:         config.Server.Host + ":" + config.Server.Port,
		Handler:      NewRouter(config),
		ReadTimeout:  config.Server.Timeout.Read * time.Second,
		WriteTimeout: config.Server.Timeout.Write * time.Second,
		IdleTimeout:  config.Server.Timeout.Idle * time.Second,
	}

	// Handle ctrl+c/ctrl+x interrupt
	signal.Notify(runChan, os.Interrupt, syscall.SIGTSTP)

	// Alert the user that the server is starting
	log.Infof("Server is starting on %s\n", server.Addr)

	// Run the server on a new goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				// Normal interrupt operation, ignore
			} else {
				log.Fatalf("Server failed to start due to err: %v", err)
			}
		}
	}()

	// Block on this channel listen for those previously defined syscalls assign
	// to variable so we can let the user know why the server is shutting down
	interuppt := <-runChan

	// If we get one of the pre-prescribed syscalls, gracefully terminate the server
	// while alerting the user
	log.Infof("Server is shutting down due to %+v\n", interuppt)
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server was unable to gracefully shutdown due to err: %+v", err)
	}
}

func (source OpenSslSource) buildCAHash(algorithm crypto.Hash) (issuerHash []byte, err error) {
	h := algorithm.New()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(source.caCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		log.Errorf("Error parsing CA certificate public key info: %v", err)
		return nil, err
	}
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerHash = h.Sum(nil)
	return issuerHash, nil
}

func getIssuer(cert *x509.Certificate) *x509.Certificate {
	var issuer *x509.Certificate
	var err error
	for _, issuingCert := range cert.IssuingCertificateURL {
		issuer, err = fetchCert(issuingCert)
		if err != nil {
			continue
		}
		break
	}

	return issuer

}

func (source OpenSslSource) validateCrl() (bool, error) {
	var shouldFetchCRL = false
	if source.caCrl.HasExpired(time.Now()) {
		log.Criticalf("CRL for Issuer '%s' has expired!", source.caCrl.TBSCertList.Issuer.String())
		shouldFetchCRL = true
	}

	if shouldFetchCRL {
		issuer := getIssuer(source.ocspCert)
		for _, url := range source.ocspCert.CRLDistributionPoints {
			crl, err := fetchCRL(url)
			if err != nil {
				log.Warningf("failed to fetch CRL: %v", err)
				return false, err
			}

			// check CRL signature
			if issuer != nil {
				err = issuer.CheckCRLSignature(crl)
				if err != nil {
					log.Warningf("failed to verify CRL: %v", err)
					return false, err
				}
			}

			source.crlLock.Lock()
			source.caCrl = crl
			source.crlLock.Unlock()

			break
		}

	}

	return true, nil
}

// Response required function for OCSP responder interface
// https://github.com/cloudflare/cfssl/blob/master/revoke/revoke.go
func (source OpenSslSource) Response(request *ocsp.Request) ([]byte, http.Header, error) {
	caHash, err := source.buildCAHash(request.HashAlgorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("Error building CA certificate hash with algorithm %d: %v", request.HashAlgorithm, err)
	}
	if bytes.Compare(request.IssuerKeyHash, caHash) != 0 {
		return nil, nil, fmt.Errorf("Request issuer key does not match CA subject key hash")
	}

	// check response cache for serial number
	cacheKey := request.SerialNumber.String()
	response, present := source.cached[cacheKey]
	if present {
		return response, nil, nil
	}

	var revocationTime time.Time
	certRecord, found := source.certIndex[cacheKey]
	if !found {
		// no record in index
		return ocsp.UnauthorizedErrorResponse, nil, errors.New("Request OCSP Response not found") //cfocsp.ErrNotFound
	}

	if certRecord.status == revoked {
		revocationTime = certRecord.revocationTime
	} else {
		// make sure Crl is valid/up-to-date
		validCrl, err := source.validateCrl()
		if !validCrl || err != nil {
			response, err = source.buildServerFailedResponse(request.SerialNumber)
			return response, nil, fmt.Errorf("unable to validate CRL: %v", err)
		}

		found = false
		for _, revoked := range source.caCrl.TBSCertList.RevokedCertificates {
			if request.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				found = true
				revocationTime = revoked.RevocationTime
				break
			}
		}
	}

	if !revocationTime.IsZero() {
		log.Infof("Certificate with serial number %s is revoked", cacheKey)
		response, err = source.buildRevokedResponse(request.SerialNumber, revocationTime)
		if err != nil {
			return nil, nil, fmt.Errorf("could not build response %v", err)
		}
		source.cached[cacheKey] = response
		return response, nil, nil
	}

	if certRecord.status == expired || certRecord.expirationTime.Before(time.Now()) {
		// certificate is expired, store unauthorized response in cache
		log.Infof("Certificate with serial %s expired at %s, returning unauthorized", cacheKey, certRecord.expirationTime)
		response = ocsp.UnauthorizedErrorResponse
		source.cached[cacheKey] = response
	} else {
		log.Infof("Certificate with serial %s is valid", cacheKey)
		response, err = source.buildOkResponse(request.SerialNumber)
		if err != nil {
			return nil, nil, fmt.Errorf("could not build response %v", err)
		}
	}
	return response, nil, nil
}

func (source OpenSslSource) buildServerFailedResponse(serialNumber *big.Int) ([]byte, error) {
	template := ocsp.Response{
		SerialNumber: serialNumber,
		Status:       ocsp.ServerFailed,
		ThisUpdate:   time.Now(),
		Certificate:  source.ocspCert,
	}
	return source.buildResponse(template)
}

func (source OpenSslSource) buildRevokedResponse(serialNumber *big.Int, revocationTime time.Time) ([]byte, error) {
	template := ocsp.Response{
		SerialNumber: serialNumber,
		Status:       ocsp.Revoked,
		ThisUpdate:   time.Now(),
		Certificate:  source.ocspCert,
	}
	template.RevokedAt = revocationTime
	template.RevocationReason = ocsp.Unspecified
	return source.buildResponse(template)
}

func (source OpenSslSource) buildOkResponse(serialNumber *big.Int) (ocspResponse []byte, err error) {
	template := ocsp.Response{
		SerialNumber: serialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
		Certificate:  source.ocspCert,
	}
	return source.buildResponse(template)
}

func (source OpenSslSource) buildResponse(template ocsp.Response) (ocspResponse []byte, err error) {
	ocspResponse, err = ocsp.CreateResponse(
		source.caCert, source.ocspCert, template, *source.ocspSigner)
	return
}
