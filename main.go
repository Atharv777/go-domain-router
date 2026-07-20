package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"golang.org/x/crypto/acme/autocert"
)

var routes = map[string]string{
	"lumatozer.org": "http://google.com",
	"ltz.sh":        "http://localhost:3001",
}

func reverseProxy(w http.ResponseWriter, r *http.Request) {
	log.Printf("Incoming request: Host=%s Path=%s\n ", r.Host, r.URL.Path)
	target, ok := routes[r.Host]

	if !ok {
		http.Error(w, "Domain not configured with Lumatozer", 404)
		return
	}

	targetURL, err := url.Parse(target)

	if err != nil {
		http.Error(w, "Bad target", 500)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	log.Printf("Routing %s → %s\n", r.Host, target)

	proxy.ServeHTTP(w, r)
}

func main() {
	certManager := &autocert.Manager{
		Cache:      autocert.DirCache("./certs"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("lumatozer.org"),
	}

	go func() {
		log.Println("Starting HTTP (port 80) for ACME...")
		err := http.ListenAndServe(":80", certManager.HTTPHandler(nil))
		if err != nil {
			log.Fatal(err)
		}
	}()

	server := &http.Server{
		Addr:    ":443",
		Handler: http.HandlerFunc(reverseProxy),
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	log.Println("HTTPS server running on :443")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

