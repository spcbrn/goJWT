package main

// User type for request/response body JSON
type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// JWT Token type for request/response body JSON
type JWT struct {
	Token string `json:"token"`
}

// Error type for response body JSON
type Error struct {
	Message string `json:"message"`
}

// Restricted data type for protected endpoint
type Restricted struct {
	Data string `json:"data"`
}
