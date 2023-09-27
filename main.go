package main

import (
	"Golang/Request"
	"Golang/Response"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Danny-Dasilva/CycleTLS/cycletls"
	"github.com/dsnet/compress/brotli"
	"github.com/gorilla/mux"
)

func main() {
	port := "8000"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	err := os.Setenv("tls13", "1")
	if err != nil {
		log.Println(err.Error())
	}

	router := mux.NewRouter()
	router.HandleFunc("/status", CheckStatus).Methods("GET")
	router.HandleFunc("/", Handle).Methods("POST")
	fmt.Println("The proxy server is running")
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func CheckStatus(responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode("good")
}

func Handle(responseWriter http.ResponseWriter, request *http.Request) {
	responseWriter.Header().Set("Content-Type", "application/json")

	var handleRequest Request.HandleRequest
	json.NewDecoder(request.Body).Decode(&handleRequest)
	client := cycletls.Init()

	resp, err := client.Do(handleRequest.Url, cycletls.Options{
		Cookies: handleRequest.Cookies,
		//InsecureSkipVerify: handleRequest.InsecureSkipVerify,
		Body:            handleRequest.Body,
		Proxy:           handleRequest.Proxy,
		Timeout:         handleRequest.Timeout,
		Headers:         handleRequest.Headers,
		Ja3:             handleRequest.Ja3,
		UserAgent:       handleRequest.UserAgent,
		DisableRedirect: handleRequest.DisableRedirect,
	}, handleRequest.Method)

	var handleResponse Response.HandleResponse

	if err != nil {
		fmt.Println(err)
		handleResponse.Success = false
		handleResponse.Error = err.Error()
		json.NewEncoder(responseWriter).Encode(handleResponse)
		return
	} else {
		fmt.Printf("[%v] %v\n", resp.Status, handleRequest.Url)
	}

	handleResponse.Success = true
	handleResponse.Payload = &Response.HandleResponsePayload{
		Text:    DecodeResponse(&resp),
		Headers: resp.Headers,
		Status:  resp.Status,
		//Url:     resp.Url,
	}

	for _, cookie := range handleRequest.Cookies {
		handleResponse.Payload.Cookies = append(handleResponse.Payload.Cookies, &cycletls.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Expires:  cookie.Expires,
			MaxAge:   cookie.MaxAge,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HTTPOnly,
		})
	}

	json.NewEncoder(responseWriter).Encode(handleResponse)
}

func DecodeResponse(response *cycletls.Response) string {
	switch response.Headers["Content-Encoding"] {
	case "gzip__":
		reader, _ := gzip.NewReader(strings.NewReader(response.Body))
		defer reader.Close()
		readerResponse, _ := ioutil.ReadAll(reader)
		return string(readerResponse)
	case "br__":
		reader, _ := brotli.NewReader(strings.NewReader(response.Body), &brotli.ReaderConfig{})
		defer reader.Close()
		readerResponse, _ := ioutil.ReadAll(reader)
		return string(readerResponse)
	default:
		return response.Body
	}
}
