package controllers

import (
	"net/http"

	"../models"
	"../utils"
)

// Protected serves up token protected resources
func (c Controller) Protected() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		utils.ResponseJSON(w, models.Protected{
			Data: "Here is your super secret resource.",
		})
	}
}
