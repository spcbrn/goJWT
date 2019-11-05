package userRepository

import (
	"database/sql"
	"log"

	"../../models"
)

// UserRepository struct for user db interactions
type UserRepository struct{}

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// Signup adds new user record to db
func (u UserRepository) Signup(db *sql.DB, user models.User) (models.User, error) {
	// generate and execute sql query to create new user record
	stmt := "insert into users (email, password) values($1, $2) RETURNING id;"
	err := db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		return user, err
	}

	logFatal(err)

	user.Password = ""
	return user, nil
}

// Login retrieves requested user record from db
func (u UserRepository) Login(db *sql.DB, user models.User) (models.User, error) {
	// retrieve requested user's record from database
	row := db.QueryRow("select * from users where email=$1", user.Email)
	// scan retrieved values onto correspondant fields on user
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		return user, err
	}

	return user, nil
}
