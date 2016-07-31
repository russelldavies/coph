/*
coph: CUPS Over Plain HTTP
*/
package main

/*
#cgo CFLAGS: -I. -I./cups
#cgo LDFLAGS: -L./cups/cups -lcups

#include "cups/cups.h"

char *cupsPassword;

char const *passwordCallback(char const *prompt) {
    return cupsPassword;
}

int streamPrint(char *server, char *username, char *password,
                char *printerName, char *title, char *buffer,
                size_t bufferSize) {
    cupsSetServer(server);
    cupsSetUser(username);
    cupsPassword = password;
    cupsSetPasswordCB(passwordCallback);

    cups_dest_t *dests;
    int numDests = cupsGetDests(&dests);
    if (numDests == 0) {
        return -1;
    }
    cups_dest_t *dest = cupsGetDest(printerName, NULL, numDests, dests);
    if (dest == NULL) {
        return -1;
    }

    if (title == NULL) {
        title = "title";
    }
    int jobId = cupsCreateJob(CUPS_HTTP_DEFAULT, dest->name, title, 0, NULL);
    if (jobId == 0) {
        int errorCode = cupsLastError();
        char const *errorMsg = cupsLastErrorString();
        return -1;
    }
    cupsStartDocument(CUPS_HTTP_DEFAULT, dest->name, jobId, title, CUPS_FORMAT_RAW, 1);
    cupsWriteRequestData(CUPS_HTTP_DEFAULT, buffer, bufferSize);
    cupsFinishDocument(CUPS_HTTP_DEFAULT, dest->name);
    cupsFreeDests(numDests, dests);
    return jobId;
}
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
	username      = flag.String("username", "", "coph username")
	password      = flag.String("password", "", "coph password")
	port          = flag.Int("port", 6310, "Port that coph listens on")
	addr          string
	cupsServer    = flag.String("cups-server", "localhost", "CUPS server to connect to")
	cupsUsername  = flag.String("cups-username", "", "CUPS username")
	cupsPassword  = flag.String("cups-password", "", "CUPS password")
	hostname      = "coph"
	silent        = flag.Bool("s", false, "Silent; do not output anything")
	showTimestamp = flag.Bool("t", false, "Show timestamp; include timestamp in log messages")

	stats          map[string]int64 = make(map[string]int64)
	statsDurations                  = map[string]time.Duration{"day": time.Hour * 24,
		"week":  time.Hour * 24 * 7,
		"month": time.Hour * 24 * 30}
)

func main() {
	flag.Parse()
	if *silent {
		log.SetOutput(ioutil.Discard)
	}
	if !*showTimestamp {
		log.SetFlags(0)
	}
	switch {
	case len(*username) == 0:
		log.Fatalf("Missing required --username parameter")
	case len(*password) == 0:
		log.Fatalf("Missing required --password parameter")
	case len(*cupsUsername) == 0:
		log.Fatalf("Missing required --cups-username parameter")
	case len(*cupsPassword) == 0:
		log.Fatalf("Missing required --cups-password parameter")
	}

	stats["started"] = time.Now().Unix()
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

func httpHandler(res http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		showStats(res, req)
	case http.MethodPost:
		printJob(res, req)
	case http.MethodOptions:
		res.Header().Set("Allow", "OPTIONS, GET, POST")
	default:
		http.Error(res, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func authenticate(res http.ResponseWriter, req *http.Request) bool {
	authUsername, authPassword, authOK := req.BasicAuth()
	switch {
	case !authOK:
		http.Error(res, "Basic auth must be supplied", http.StatusUnauthorized)
		return false
	case authUsername != *username || authPassword != *password:
		http.Error(res, "Invalid auth", http.StatusUnauthorized)
		return false
	}
	return true
}

func printJob(res http.ResponseWriter, req *http.Request) {
	if !authenticate(res, req) {
		return
	}
	var statusMsg string
	statusCode := http.StatusBadRequest

	printerName := req.FormValue("printer_name")
	if len(printerName) == 0 {
		statusMsg = "No printer name specified"
		http.Error(res, "'printer_name' form key must be specified", statusCode)
	}
	file, _, err := req.FormFile("file")
	if err != nil {
		statusMsg = err.Error()
		http.Error(res, "'file' form key must be specified", statusCode)
	} else {
		defer file.Close()
	}

	var size int64
	if err == nil {
		buffer := new(bytes.Buffer)
		var err error
		size, err = io.Copy(buffer, file)
		if err != nil {
			statusMsg = err.Error()
			http.Error(res, "Bad data", statusCode)
		} else {
			jobId := int(C.streamPrint(
				C.CString(*cupsServer),
				C.CString(*cupsUsername),
				C.CString(*cupsPassword),
				C.CString(printerName),
				nil,
				(*C.char)(unsafe.Pointer(&buffer.Bytes()[0])),
				C.size_t(size)))
			if jobId > 0 {
				fmt.Fprintf(res, "%d", jobId)
				statusMsg = fmt.Sprintf("Printed OK, job id %d", jobId)
				statusCode = http.StatusOK
				updateStats()
			} else {
				statusMsg = "Failed to print"
				http.Error(res, statusMsg, statusCode)
			}
		}
	}
	log.Printf("%s - %s %d - %s printer, %d bytes; %s", req.RemoteAddr, req.Proto,
		statusCode, printerName, size, statusMsg)
}

func showStats(res http.ResponseWriter, req *http.Request) {
	if !authenticate(res, req) {
		return
	}
	fmt.Fprintf(res, "coph\n~~~~\n")
	fmt.Fprintf(res, "Started: %s\n", time.Unix(stats["started"], 0))
	fmt.Fprintf(res, "Submitted print jobs, per:\n")
	fmt.Fprintf(res, "* Day: %d\n", stats["dayCount"])
	fmt.Fprintf(res, "* Week: %d\n", stats["weekCount"])
	fmt.Fprintf(res, "* Month: %d\n", stats["monthCount"])
	fmt.Fprintf(res, "* Total (since started): %d\n", stats["total"])
}

func updateStats() {
	for prefix, duration := range statsDurations {
		count := prefix + "Count"
		start := prefix + "Start"

		if time.Now().Sub(time.Unix(stats[start], 0)) <= duration {
			stats[count] += 1
		} else {
			stats[count] = 1
			stats[start] = time.Now().Unix()
		}
	}
	stats["total"] += 1
}
