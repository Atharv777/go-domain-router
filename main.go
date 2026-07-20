package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

var routes = map[string]string{
	"lumatozer.org": "http://localhost:5000",
	"ltz.sh":        "http://localhost:5001",
}

func CertHostPolicy(ctx context.Context, host string) error {
	if _, ok := routes[host]; ok {
		return nil
	}
	return fmt.Errorf("unauthorized domain: %s", host)
}

func reverseProxy(w http.ResponseWriter, r *http.Request) {
	log.Printf("Incoming request: Host=%s Path=%s\n ", r.Host, r.URL.Path)
	host := strings.Split(r.Host, ":")[0]
	target, ok := routes[host]

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
		HostPolicy: CertHostPolicy,
	}

	go func() {
		log.Println("Starting HTTP (port 80) for ACME...")
		err := http.ListenAndServe(":80", certManager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := strings.Split(r.Host, ":")[0]
			if net.ParseIP(host) != nil {
				http.Redirect(w, r, "https://lumatozer.org", http.StatusMovedPermanently)
				return
			}
			http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
		})))

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
