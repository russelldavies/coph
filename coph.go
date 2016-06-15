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
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
	"unsafe"
)

var (
	username     = flag.String("username", "", "coph username")
	password     = flag.String("password", "", "coph password")
	port         = flag.Int("port", 6631, "Port that coph listens on")
	addr         string
	cupsServer   = flag.String("cups-server", "localhost", "CUPS server to connect to")
	cupsUsername = flag.String("cups-username", "", "CUPS username")
	cupsPassword = flag.String("cups-password", "", "CUPS password")
)

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().UTC().Format(time.RFC3339) + " " + string(bytes))
}

func main() {
	log.SetFlags(0)
	log.SetOutput(new(logWriter))
	flag.Parse()

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
	addr = ":" + strconv.Itoa(*port)

	http.HandleFunc("/", httpHandler)
	log.Printf("Starting server on %s", addr)
	log.Printf("CUPS server is %s", *cupsServer)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	authUsername, authPassword, authOK := r.BasicAuth()
	log.Printf("%b", authOK)
	switch {
	case !authOK:
		http.Error(w, "Basic auth must be supplied", http.StatusUnauthorized)
		return
	case authUsername != *username || authPassword != *password:
		http.Error(w, "Invalid auth", http.StatusUnauthorized)
		return
	}
	statusCode := http.StatusOK
	var errorMsg string

	printerName := r.FormValue("printer_name")
	if len(printerName) == 0 {
		statusCode = http.StatusBadRequest
		errorMsg = "No printer name specified"
		http.Error(w, "'printer_name' form key must be specified", statusCode)
	}
	file, _, err := r.FormFile("data")
	if err != nil {
		statusCode = http.StatusBadRequest
		errorMsg = err.Error()
		http.Error(w, "'data' form key must be specified", statusCode)
	} else {
		defer file.Close()
	}

	if statusCode == http.StatusOK {
		buffer := new(bytes.Buffer)
		size, err := io.Copy(buffer, file)
		if err != nil {
			statusCode = http.StatusBadRequest
			errorMsg = err.Error()
			http.Error(w, "Bad data", statusCode)
		} else {
			jobId := print(printerName, buffer, size)
			if jobId > 0 {
				fmt.Fprintf(w, "%d", jobId)
			} else {
				statusCode = http.StatusBadRequest
				errorMsg = "Failed to print"
				http.Error(w, errorMsg, statusCode)
			}
		}
	}
	log.Printf("%s %d: %s; %d; %s", r.Proto, statusCode, r.RemoteAddr,
		r.ContentLength, errorMsg)
}

func print(printerName string, buffer *bytes.Buffer, size int64) int {
	return int(C.streamPrint(C.CString(*cupsServer), C.CString(*cupsUsername),
		C.CString(*cupsPassword), C.CString(printerName), nil,
		(*C.char)(unsafe.Pointer(&buffer.Bytes()[0])), C.size_t(size)))
}
