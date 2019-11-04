package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"
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

	return error.Message
}

// take passed in interface object and send as response in JSON
func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

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

// GenerateToken generates a new jwt token with grant "course"
func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"

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
	fmt.Println("protectedEndpoint invoked.")
}

// TokenVerifyMiddleware validates that the bearer token is valid and grants access to protected endpoints
func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("there was an error")
				}

				return []byte("secret"), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid token."
			respondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}

	})
}
