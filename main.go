package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	err := dbConnect()
	if err != nil {
		log.Fatal(err)
		return
	}

	r := mux.NewRouter()

	r.HandleFunc("/signup", signup).Methods("POST")
	r.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/protected", TokenVerifyMiddleware(protectedEndpoint)).Methods("GET")

	log.Println("Serving port 3042...")
	log.Fatal(http.ListenAndServe(":3042", r))
}
