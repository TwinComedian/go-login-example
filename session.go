package main

import (
	"errors"
	"fmt"
	"net/http"
)

var ErrAuth = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		fmt.Println("error happend here - 1")
		return ErrAuth
	}

	// Get the Session Token from the cookie
	st, err := r.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		fmt.Println("error happened here - 2")
		return ErrAuth
	}

	// Get the Session Token from the headers
	csrf := r.Header.Get("X-CSRF-Token")
	if csrf != user.CSRFToken || csrf == "" {
		fmt.Println("error happened here - 3")
		return ErrAuth
	}

	return nil
}
