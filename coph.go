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
	"unsafe"
)

var (
	server   = flag.String("server", "localhost:631", "CUPS server to connect to")
	username = flag.String("username", "", "CUPS username")
	password = flag.String("password", "", "CUPS password")
	port     = flag.Int("port", 8080, "HTTP server port")
	addr     string
)

func main() {
	flag.Parse()

	switch {
	case len(*username) == 0:
		log.Fatalf("Missing required --username parameter")
	case len(*password) == 0:
		log.Fatalf("Missing required --password parameter")
	}
	addr = ":" + strconv.Itoa(*port)

	http.HandleFunc("/", httpHandler)
	log.Printf("Starting server on %s", addr)
	log.Printf("CUPS server is %s", *server)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
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
	return int(C.streamPrint(C.CString(*server), C.CString(*username),
		C.CString(*password), C.CString(printerName), nil,
		(*C.char)(unsafe.Pointer(&buffer.Bytes()[0])), C.size_t(size)))
}
