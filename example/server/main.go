package main

import (
	_ "embed"
	"fmt"
	"log"
	"net/http"
)

//go:embed index.html
var index []byte

func main() {
	fmt.Printf("please open http://localhost:8888")

	log.Fatalln(http.ListenAndServe(":8888", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; report-uri http://localhost:8080; report-to default; ")
		w.Header().Set("Content-Encoding", "text/html")
		w.Header().Set("Report-To", `{"max_age": 10886400, "endpoints": [{"url": "http://localhost:8080"}]}`)
		_, _ = w.Write(index)
		log.Println("Request served")
	})))
}
