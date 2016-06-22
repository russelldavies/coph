/*
coph: CUPS Over Plain HTTP
*/
package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lstreamprint -lcups

#include "streamprint.h"
*/
import "C"

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"
	"unsafe"
)

var (
	username     = flag.String("username", "", "coph username")
	password     = flag.String("password", "", "coph password")
	port         = flag.Int("port", 6310, "Port that coph listens on")
	addr         string
	cupsServer   = flag.String("cups-server", "localhost", "CUPS server to connect to")
	cupsUsername = flag.String("cups-username", "", "CUPS username")
	cupsPassword = flag.String("cups-password", "", "CUPS password")
	hostname     = "coph"
	silent       = flag.Bool("s", false, "Silent; do not output anything")
	showTimestamp  = flag.Bool("t", false, "Show timestamp; include timestamp in log messages")
)

func main() {
	flag.Parse()
	switch {
	case *silent:
		log.SetOutput(ioutil.Discard)
	case *showTimestamp == false:
		log.SetFlags(0)
	case len(*username) == 0:
		log.Fatalf("Missing required --username parameter")
	case len(*password) == 0:
		log.Fatalf("Missing required --password parameter")
	case len(*cupsUsername) == 0:
		log.Fatalf("Missing required --cups-username parameter")
	case len(*cupsPassword) == 0:
		log.Fatalf("Missing required --cups-password parameter")
	}

	addr = ":" + strconv.Itoa(*port)
	hostname, _ = os.Hostname()

	s := &http.Server{
		Addr:      addr,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*generateCert()}},
	}
	http.HandleFunc("/", httpHandler)

	log.Printf("Starting server %s on %s", hostname, addr)
	log.Printf("CUPS server is %s", *cupsServer)
	// Empty paths can be passed in as function will use Server.TLSConfig
	log.Fatal(s.ListenAndServeTLS("", ""))
}

func generateCert() *tls.Certificate {
	log.Print("Generating TLS certificate")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %s", err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour), // 20 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	authUsername, authPassword, authOK := r.BasicAuth()
	switch {
	case !authOK:
		http.Error(w, "Basic auth must be supplied", http.StatusUnauthorized)
		return
	case authUsername != *username || authPassword != *password:
		http.Error(w, "Invalid auth", http.StatusUnauthorized)
		return
	}
	statusCode := http.StatusOK
	statusMsg := "Printed OK"

	printerName := r.FormValue("printer_name")
	if len(printerName) == 0 {
		statusCode = http.StatusBadRequest
		statusMsg = "No printer name specified"
		http.Error(w, "'printer_name' form key must be specified", statusCode)
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		statusCode = http.StatusBadRequest
		statusMsg = err.Error()
		http.Error(w, "'file' form key must be specified", statusCode)
	} else {
		defer file.Close()
	}

	var size int64
	if statusCode == http.StatusOK {
		buffer := new(bytes.Buffer)
		size, err := io.Copy(buffer, file)
		if err != nil {
			statusCode = http.StatusBadRequest
			statusMsg = err.Error()
			http.Error(w, "Bad data", statusCode)
		} else {
			jobId := print(printerName, buffer, size)
			if jobId > 0 {
				fmt.Fprintf(w, "%d", jobId)
			} else {
				statusCode = http.StatusBadRequest
				statusMsg = "Failed to print"
				http.Error(w, statusMsg, statusCode)
			}
		}
	}
	log.Printf("%s - %s %d - %s printer, %d bytes; %s", r.RemoteAddr, r.Proto,
		statusCode, printerName, size, statusMsg)
}

func print(printerName string, buffer *bytes.Buffer, size int64) int {
	return int(C.streamPrint(C.CString(*cupsServer), C.CString(*cupsUsername),
		C.CString(*cupsPassword), C.CString(printerName), nil,
		(*C.char)(unsafe.Pointer(&buffer.Bytes()[0])), C.size_t(size)))
}
