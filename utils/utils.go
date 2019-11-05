package utils

import (
	"encoding/json"
	"net/http"

	"../models"
)

// RespondWithError - take in error struct and status code and send to client
func RespondWithError(w http.ResponseWriter, status int, error models.Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

// VerifyReqUserData - check that the incoming request body for signup/login has both a valid email and a password
// if not, send appropriate error response
func VerifyReqUserData(w http.ResponseWriter, user models.User, error models.Error) string {
	if user.Email == "" {
		error.Message = "Email is missing."
		RespondWithError(w, http.StatusBadRequest, error)
		return error.Message
	}
	if user.Password == "" {
		error.Message = "Password is missing."
		RespondWithError(w, http.StatusBadRequest, error)
		return error.Message
	}

	return ""
}

// ResponseJSON - take passed in interface object and send as response in JSON
func ResponseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}
