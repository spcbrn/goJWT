package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error

	// decode user property off of request body
	// by passing in the address to our user type object the fields will be populated
	// with the data present on the request body
	json.NewDecoder(r.Body).Decode(&user)

	// check that both email and password fields have content
	msg := verifyReqUserData(w, user, error)
	if msg != "" {
		return
	}

	// generate byte slice hash from password, then cast to string and replace on user object
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}
	user.Password = string(hash)

	// generate and execute sql query to create new user record
	stmt := "insert into users (email, password) values($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	// if query fails return server error
	if err != nil {
		error.Message = "Server error."
		respondWithError(w, http.StatusInternalServerError, error)
		return
	}

	// if successful return user object with id
	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var jwt JWT
	var error Error

	json.NewDecoder(r.Body).Decode(&user)

	msg := verifyReqUserData(w, user, error)
	if msg != "" {
		return
	}

	// grab plain text password sent from client
	pswd := user.Password

	// retrieve requested user's record from database
	row := db.QueryRow("select * from users where email=$1", user.Email)
	// scan retrieved values onto correspondant fields on user
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			respondWithError(w, http.StatusBadRequest, error)
			return
		}
		log.Fatal(err)
	}

	// grab hashed password returned from db
	hashedPswd := user.Password

	// compare hashed pw with plain text input, returning invalid password error if they mismatch
	err = bcrypt.CompareHashAndPassword([]byte(hashedPswd), []byte(pswd))
	if err != nil {
		error.Message = "The provided password is invalid."
		respondWithError(w, http.StatusUnauthorized, error)
		return
	}

	// generate new jwt token to grant to client
	token, err := GenerateToken(user)
	if err != nil {
		log.Fatal(err)
	}

	// return newly generated token to client
	w.WriteHeader(http.StatusOK)
	jwt.Token = token
	responseJSON(w, jwt)
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	responseJSON(w, Restricted{
		Data: "super secret resource",
	})
}
