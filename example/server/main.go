package main

import (
	_ "embed"
	"log"
	"net/http"
)

//go:embed index.html
var index []byte

func main() {
	log.Fatalln(http.ListenAndServe(":8888", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; report-uri https://csp.monitoring.mzg.bestbytes.net; report-to default; ")
		w.Header().Set("Content-Encoding", "text/html")
		w.Header().Set("Report-To", `{"max_age": 10886400, "endpoints": [{"url": "https://csp.monitoring.mzg.bestbytes.net"}]}`)
		_, _ = w.Write(index)
		log.Println("Request served")
	})))
}
