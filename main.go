package main

import (
	"database/sql"
	"log"
	"net/http"

	"./controllers"
	"./driver"
	"./utils"

	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
)

var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {
	db = driver.ConnectDB()
	controller := controllers.Controller{}

	r := mux.NewRouter()

	r.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	r.HandleFunc("/login", controller.Login(db)).Methods("POST")
	r.HandleFunc("/protected", utils.TokenVerifyMiddleware(controller.Protected())).Methods("GET")

	log.Println("Serving port 3042...")
	log.Fatal(http.ListenAndServe(":3042", r))
}
