package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"./models"
	"./utils"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"
)

func signup(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var error models.Error

	// decode user property off of request body
	// by passing in the address to our user type object the fields will be populated
	// with the data present on the request body
	json.NewDecoder(r.Body).Decode(&user)

	// check that both email and password fields have content
	msg := utils.VerifyReqUserData(w, user, error)
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
		utils.RespondWithError(w, http.StatusInternalServerError, error)
		return
	}

	// if successful return user object with id
	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	utils.ResponseJSON(w, user)
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

func login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var jwt models.JWT
	var error models.Error

	json.NewDecoder(r.Body).Decode(&user)

	msg := utils.VerifyReqUserData(w, user, error)
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
			utils.RespondWithError(w, http.StatusBadRequest, error)
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
		utils.RespondWithError(w, http.StatusUnauthorized, error)
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
	utils.ResponseJSON(w, jwt)
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	utils.ResponseJSON(w, models.Protected{
		Data: "Here is your super secret resource.",
	})
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
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid token."
			utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}

	})
}
