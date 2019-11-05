package main

import (
	"database/sql"
	"log"

	"github.com/lib/pq"
)

var db *sql.DB

func dbConnect() error {
	pgURL, err := pq.ParseURL("postgres://hbqbvsuvzkiwyv:96d4d273802750abef0437f1bfe640787b5a514afec668bd32bb0536834ad5f4@ec2-23-21-76-49.compute-1.amazonaws.com:5432/d8fn2og7m2c9ag")

	if err != nil {
		log.Fatal(err)
		return err
	}

	db, err = sql.Open("postgres", pgURL)

	if err != nil {
		log.Fatal(err)
		return err
	}

	err = db.Ping()

	if err != nil {
		log.Fatal(err)
		return err
	}

	return nil
}
