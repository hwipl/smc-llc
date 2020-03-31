package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

var (
	httpBuffer buffer
)

// printHttp prints the output stored in buffer to http clients
func printHTTP(w http.ResponseWriter, r *http.Request) {
	b := httpBuffer.copyBuffer()
	if _, err := io.Copy(w, b); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// setHTTPOutput sets the standard output to http and starts a http server
func setHTTPOutput() {
	stdout = &httpBuffer
	stderr = &httpBuffer

	http.HandleFunc("/", printHTTP)
	go http.ListenAndServe(*httpListen, nil)
}
