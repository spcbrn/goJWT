package main

import (
	"encoding/json"
	"net/http"
)

// take in error struct and status code and send to client
func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

// check that the incoming request body for signup/login has both a valid email and a password
// if not, send appropriate error response
func verifyReqUserData(w http.ResponseWriter, user User, error Error) string {
	if user.Email == "" {
		error.Message = "Email is missing."
		respondWithError(w, http.StatusBadRequest, error)
		return error.Message
	}
	if user.Password == "" {
		error.Message = "Password is missing."
		respondWithError(w, http.StatusBadRequest, error)
		return error.Message
	}

	return ""
}

// take passed in interface object and send as response in JSON
func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}
