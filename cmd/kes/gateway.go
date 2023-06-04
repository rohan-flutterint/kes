// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes-go"
	kesconf "github.com/minio/kes/edge"
	"github.com/minio/kes/internal/api"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/edge"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/internal/keystore"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/mtls"
	"github.com/minio/kes/internal/sys"
)

func startEdgeServer(filename, addr string) {
	var mlock bool
	if runtime.GOOS == "linux" {
		mlock = mlockall() == nil
	}

	if isTerm(os.Stderr) {
		style := tui.NewStyle().Foreground(tui.Color("#ac0000")) // red
		log.Default().SetPrefix(style.Render("Error: "))
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelCtx()

	config, err := loadGatewayConfig(filename, addr)
	if err != nil {
		cli.Fatal(err)
	}
	tlsConfig, err := newTLSConfig(config)
	if err != nil {
		cli.Fatal(err)
	}
	gwConfig, err := newGatewayConfig(ctx, config, tlsConfig)
	if err != nil {
		cli.Fatal(err)
	}

	buffer, err := gatewayMessage(config, tlsConfig, mlock)
	if err != nil {
		cli.Fatal(err)
	}
	cli.Println(buffer.String())

	server := https.NewServer(&https.Config{
		Addr:      config.Addr,
		Handler:   api.NewEdgeRouter(gwConfig),
		TLSConfig: tlsConfig,
	})
	go func(ctx context.Context) {
		if runtime.GOOS == "windows" {
			return
		}

		sighup := make(chan os.Signal, 10)
		signal.Notify(sighup, syscall.SIGHUP)
		defer signal.Stop(sighup)

		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				cli.Println("SIGHUP signal received. Reloading configuration...")
				config, err := loadGatewayConfig(filename, addr)
				if err != nil {
					log.Printf("failed to read server config: %v", err)
					continue
				}
				tlsConfig, err := newTLSConfig(config)
				if err != nil {
					log.Printf("failed to initialize TLS config: %v", err)
					continue
				}
				gwConfig, err := newGatewayConfig(ctx, config, tlsConfig)
				if err != nil {
					log.Printf("failed to initialize server API: %v", err)
					continue
				}
				err = server.Update(&https.Config{
					Addr:      config.Addr,
					Handler:   api.NewEdgeRouter(gwConfig),
					TLSConfig: tlsConfig,
				})
				if err != nil {
					log.Printf("failed to update server configuration: %v", err)
					continue
				}
				buffer, err := gatewayMessage(config, tlsConfig, mlock)
				if err != nil {
					log.Print(err)
					cli.Println("Reloading configuration after SIGHUP signal completed.")
				} else {
					cli.Println(buffer.String())
				}
			}
		}
	}(ctx)

	go func(ctx context.Context) {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
			case <-ticker.C:
				tlsConfig, err := newTLSConfig(config)
				if err != nil {
					log.Printf("failed to reload TLS configuration: %v", err)
					continue
				}
				if err = server.UpdateTLS(tlsConfig); err != nil {
					log.Printf("failed to update TLS configuration: %v", err)
				}
			}
		}
	}(ctx)

	if err := server.Start(ctx); err != nil && err != http.ErrServerClosed {
		cli.Fatal(err)
	}
}

func description(config *kesconf.ServerConfig) (kind string, endpoint []string, err error) {
	if config.KeyStore == nil {
		return "", nil, errors.New("no KMS backend specified")
	}

	switch kms := config.KeyStore.(type) {
	case *kesconf.FSKeyStore:
		kind = "Filesystem"
		if abs, err := filepath.Abs(kms.Path); err == nil {
			endpoint = []string{abs}
		} else {
			endpoint = []string{kms.Path}
		}
	case *kesconf.KESKeyStore:
		kind = "KES"
		endpoint = kms.Endpoints
	case *kesconf.VaultKeyStore:
		kind = "Hashicorp Vault"
		endpoint = []string{kms.Endpoint}
	case *kesconf.FortanixKeyStore:
		kind = "Fortanix SDKMS"
		endpoint = []string{kms.Endpoint}
	case *kesconf.AWSSecretsManagerKeyStore:
		kind = "AWS SecretsManager"
		endpoint = []string{kms.Endpoint}
	case *kesconf.KeySecureKeyStore:
		kind = "Gemalto KeySecure"
		endpoint = []string{kms.Endpoint}
	case *kesconf.GCPSecretManagerKeyStore:
		kind = "GCP SecretManager"
		endpoint = []string{"Project: " + kms.ProjectID}
	case *kesconf.AzureKeyVaultKeyStore:
		kind = "Azure KeyVault"
		endpoint = []string{kms.Endpoint}
	default:
		return "", nil, fmt.Errorf("unknown KMS backend %T", kms)
	}
	return kind, endpoint, nil
}

func loadGatewayConfig(filename, addr string) (*kesconf.ServerConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config, err := kesconf.ReadServerConfigYAML(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Set config defaults
	const DefaultAddr = "0.0.0.0:7373"
	if addr != "" {
		config.Addr = addr
	}
	if config.Addr == "" {
		config.Addr = DefaultAddr
	}
	if config.Cache.Expiry == 0 {
		config.Cache.Expiry = 5 * time.Minute
	}
	if config.Cache.ExpiryUnused == 0 {
		config.Cache.ExpiryUnused = 30 * time.Second
	}

	// Verify config
	if config.Admin.IsUnknown() {
		return nil, errors.New("no admin identity specified")
	}
	if config.TLS.PrivateKey == "" {
		return nil, errors.New("no TLS private key specified")
	}
	if config.TLS.Certificate == "" {
		return nil, errors.New("no TLS certificate specified")
	}
	return config, nil
}

func newTLSConfig(config *kesconf.ServerConfig) (*tls.Config, error) {
	certificate, err := mtls.CertificateFromFile(config.TLS.Certificate, config.TLS.PrivateKey, config.TLS.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS certificate: %v", err)
	}
	if certificate.Leaf != nil {
		if len(certificate.Leaf.DNSNames) == 0 && len(certificate.Leaf.IPAddresses) == 0 {
			// Support for TLS certificates with a subject CN but without any SAN
			// has been removed in Go 1.15. Ref: https://go.dev/doc/go1.15#commonname
			// Therefore, we require at least one SAN for the server certificate.
			return nil, fmt.Errorf("invalid TLS certificate: certificate does not contain any DNS or IP address as SAN")
		}
	}

	var rootCAs *x509.CertPool
	if config.TLS.CAPath != "" {
		rootCAs, err = mtls.CertPoolFromFile(config.TLS.CAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLS CA certificates: %v", err)
		}
	}
	var clientAuth tls.ClientAuthType
	switch {
	case false:
		clientAuth = tls.RequireAndVerifyClientCert
		if config.API != nil {
			for _, api := range config.API.Paths {
				if api.InsecureSkipAuth {
					clientAuth = tls.VerifyClientCertIfGiven
					break
				}
			}
		}
	case true:
		clientAuth = tls.RequireAnyClientCert
		if config.API != nil {
			for _, api := range config.API.Paths {
				if api.InsecureSkipAuth {
					clientAuth = tls.RequestClientCert
					break
				}
			}
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   clientAuth,
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,

		MinVersion:       tls.VersionTLS12,
		CipherSuites:     fips.TLSCiphers(),
		CurvePreferences: fips.TLSCurveIDs(),
	}, nil
}

func newGatewayConfig(ctx context.Context, config *kesconf.ServerConfig, tlsConfig *tls.Config) (*edge.Node, error) {
	rConfig := &edge.Node{
		Admin: config.Admin,
	}

	if config.Log.Error {
		rConfig.ErrorLog = log.New(os.Stderr, "Error: ", log.Ldate|log.Ltime|log.Lmsgprefix)
	} else {
		rConfig.ErrorLog = log.New(ioutil.Discard, "Error: ", log.Ldate|log.Ltime|log.Lmsgprefix)
	}
	if config.Log.Audit {
		rConfig.AuditLog = log.New(os.Stdout, "", 0)
	} else {
		rConfig.AuditLog = log.New(ioutil.Discard, "", 0)
	}

	if len(config.TLS.Proxies) != 0 {
		rConfig.Proxy = &auth.TLSProxy{
			CertHeader: http.CanonicalHeaderKey(config.TLS.ForwardCertHeader),
		}
		if tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
			rConfig.Proxy.VerifyOptions = &x509.VerifyOptions{
				Roots: tlsConfig.RootCAs,
			}
		}
		for _, identity := range config.TLS.Proxies {
			if !identity.IsUnknown() {
				rConfig.Proxy.Add(identity)
			}
		}
	}

	if config.API != nil && len(config.API.Paths) > 0 {
		rConfig.APIConfig = make(map[string]edge.APIConfig, len(config.API.Paths))
		for k, v := range config.API.Paths {
			k = strings.TrimSpace(k) // Ensure that the API path starts with a '/'
			if !strings.HasPrefix(k, "/") {
				k = "/" + k
			}

			if _, ok := rConfig.APIConfig[k]; ok {
				return nil, fmt.Errorf("ambiguous API configuration for '%s'", k)
			}
			rConfig.APIConfig[k] = edge.APIConfig{
				Timeout:          v.Timeout,
				InsecureSkipAuth: v.InsecureSkipAuth,
			}
		}
	}
	policies, err := edge.NewPolicyMap(config.Policies, config.Admin)
	if err != nil {
		return nil, err
	}
	rConfig.Policies = policies

	conn, err := config.KeyStore.Connect(ctx)
	if err != nil {
		return nil, err
	}
	rConfig.Keys = keystore.NewCache(ctx, conn, &keystore.CacheConfig{
		Expiry:        config.Cache.Expiry,
		ExpiryUnused:  config.Cache.ExpiryUnused,
		ExpiryOffline: config.Cache.ExpiryOffline,
	})

	for _, k := range config.Keys {
		var cipher crypto.SecretKeyCipher
		if fips.Mode > fips.ModeNone || cpu.HasAESGCM() {
			cipher = kes.AES256
		} else {
			cipher = kes.ChaCha20
		}

		key, err := crypto.GenerateSecretKey(cipher, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create key '%s': %v", k.Name, err)
		}
		if err = rConfig.Keys.Create(ctx, k.Name, crypto.SecretKeyVersion{
			Key:       key,
			CreatedAt: time.Now().UTC(),
			CreatedBy: config.Admin,
		}); err != nil && !errors.Is(err, kes.ErrKeyExists) {
			return nil, fmt.Errorf("failed to create key '%s': %v", k.Name, err)
		}
	}

	rConfig.Metrics = metric.New()
	rConfig.AuditLog.Add(rConfig.Metrics.AuditEventCounter())
	rConfig.ErrorLog.Add(rConfig.Metrics.ErrorEventCounter())
	return rConfig, nil
}

func gatewayMessage(config *kesconf.ServerConfig, tlsConfig *tls.Config, mlock bool) (*cli.Buffer, error) {
	ip, port := serverAddr(config.Addr)
	ifaceIPs := listeningOnV4(ip)
	if len(ifaceIPs) == 0 {
		return nil, errors.New("failed to listen on network interfaces")
	}
	kmsKind, kmsEndpoints, err := description(config)
	if err != nil {
		return nil, err
	}

	var faint, item, green, red tui.Style
	if isTerm(os.Stdout) {
		faint = faint.Faint(true)
		item = item.Foreground(tui.Color("#2e42d1")).Bold(true)
		green = green.Foreground(tui.Color("#00a700"))
		red = red.Foreground(tui.Color("#a70000"))
	}

	buffer := new(cli.Buffer)
	buffer.Stylef(item, "%-12s", "Copyright").Sprintf("%-22s", "MinIO, Inc.").Styleln(faint, "https://min.io")
	buffer.Stylef(item, "%-12s", "License").Sprintf("%-22s", "GNU AGPLv3").Styleln(faint, "https://www.gnu.org/licenses/agpl-3.0.html")
	buffer.Stylef(item, "%-12s", "Version").Sprintf("%-22s", sys.BinaryInfo().Version).Stylef(faint, "%s/%s\n", runtime.GOOS, runtime.GOARCH)
	buffer.Sprintln()
	buffer.Stylef(item, "%-12s", "KMS").Sprintf("%s: %s\n", kmsKind, kmsEndpoints[0])
	for _, endpoint := range kmsEndpoints[1:] {
		buffer.Sprintf("%-12s", " ").Sprint(strings.Repeat(" ", len(kmsKind))).Sprintf("  %s\n", endpoint)
	}
	buffer.Stylef(item, "%-12s", "Endpoints").Sprintf("https://%s:%s\n", ifaceIPs[0], port)
	for _, ifaceIP := range ifaceIPs[1:] {
		buffer.Sprintf("%-12s", " ").Sprintf("https://%s:%s\n", ifaceIP, port)
	}
	buffer.Sprintln()
	if r, err := hex.DecodeString(config.Admin.String()); err == nil && len(r) == sha256.Size {
		buffer.Stylef(item, "%-12s", "Admin").Sprintln(config.Admin)
	} else {
		buffer.Stylef(item, "%-12s", "Admin").Sprintf("%-22s", "_").Styleln(faint, "[ disabled ]")
	}
	if tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		buffer.Stylef(item, "%-12s", "Mutual TLS").Sprint("on").Styleln(faint, "Verify client certificates")
	}
	switch {
	case runtime.GOOS == "linux" && mlock:
		buffer.Stylef(item, "%-12s", "Mem Lock").Stylef(green, "%-22s", "on").Styleln(faint, "RAM pages will not be swapped to disk")
	case runtime.GOOS == "linux":
		buffer.Stylef(item, "%-12s", "Mem Lock").Stylef(red, "%-22s", "off").Styleln(faint, "Failed to lock RAM pages. Consider granting CAP_IPC_LOCK")
	default:
		buffer.Stylef(item, "%-12s", "Mem Lock").Stylef(red, "%-22s", "off").Stylef(faint, "Not supported on %s/%s\n", runtime.GOOS, runtime.GOARCH)
	}
	return buffer, nil
}
