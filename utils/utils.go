package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"../models"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
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

// ComparePasswords compares hash to plain text and returns bool
func ComparePasswords(hashed string, pw string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(pw))
	if err != nil {
		return false
	}
	return true
}

// GenerateToken generates a new jwt token with grant "course"
func GenerateToken(user models.User) (string, error) {
	var err error
	secret := os.Getenv("SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tkStr, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}

	return tkStr, nil
}

// TokenVerifyMiddleware validates that the bearer token is valid and grants access to protected endpoints
func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject models.Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("there was an error")
				}

				return []byte(os.Getenv("SECRET")), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid token."
			RespondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}

	})
}
