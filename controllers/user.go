package controllers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"../models"
	userRepository "../repository/user"
	"../utils"

	"golang.org/x/crypto/bcrypt"
)

// Controller struct to export endpoint methods
type Controller struct{}

// Signup handles signing users up
func (c Controller) Signup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		userRepo := userRepository.UserRepository{}
		user, err = userRepo.Signup(db, user)

		// if query fails return server error
		if err != nil {
			error.Message = "Server error."
			utils.RespondWithError(w, http.StatusInternalServerError, error)
			return
		}

		// if successful return user object with id
		w.Header().Set("Content-Type", "application/json")
		utils.ResponseJSON(w, user)
	}
}

// Login handles logging users in
func (c Controller) Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		userRepo := userRepository.UserRepository{}
		user, err := userRepo.Login(db, user)

		if err != nil {
			error.Message = "Server error."
			utils.RespondWithError(w, http.StatusInternalServerError, error)
			return
		}

		// grab hashed password returned from db
		hashedPswd := user.Password

		// compare hashed pw with plain text input, returning invalid password error if they mismatch
		isValidPassword := utils.ComparePasswords(hashedPswd, pswd)

		// generate new jwt token to grant to client
		token, err := utils.GenerateToken(user)
		if err != nil {
			log.Fatal(err)
		}

		if isValidPassword {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Authorization", token)

			jwt.Token = token
			utils.ResponseJSON(w, jwt)
		} else {
			utils.RespondWithError(w, http.StatusUnauthorized, models.Error{Message: "Invalid password."})
		}
	}
}
