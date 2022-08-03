//go:build integration
// +build integration

package cmd

import (
	"testing"
	"time"
)

// var a = authService{Base: "http://localhost:8001"}

// User should not be able to login with a wrong username/password
func TestWrongUsernamePassword(t *testing.T) {
	// if a.Login("user1", "wrongpassword").Token != "" {
	// 	t.Fail()
	// }
	testsignParams := &testsignParameters{}
	testsignParams.url = "https://moatads.com"
	testsignParams.serverAddress = "localhost:3000"
	testsignParams.body = ""
	testsignParams.signingTimeout = 5 * time.Millisecond
	signRequest(testsignParams)
}

// // User should be able to login with the right username/password
// func TestCorrectUsernamePassword(t *testing.T) {
// 	if a.Login("user1", "pass1").Token == "" {
// 		t.Fail()
// 	}
// }

// // A user's request should be rejected if the user does not
// // have a valid session token
// func TestInvalidUserRequestAuthentication(t *testing.T) {
// 	username := "user1"
// 	lr := a.Login(username, "wrongpassword")
// 	if a.Authenticate(username, lr.Token) {
// 		t.Fail()
// 	}
// }

// // A user's request should be successfully authenticated if the user
// // has a valid session token
// func TestUserRequestAuthentication(t *testing.T) {
// 	username := "user1"
// 	lr := a.Login(username, "pass1")
// 	if !a.Authenticate(username, lr.Token) {
// 		t.Fail()
// 	}
// }

// // A user's request should be rejected the user has logged out
// func TestUserRequestAuthenticationAfterLoggingOut(t *testing.T) {
// 	username := "user1"
// 	// Login
// 	lr := a.Login(username, "pass1")

// 	// Test that the user is logged out successfully
// 	if !a.Logout(username, lr.Token) {
// 		t.Fail()
// 	}

// 	//The user's request after logging out should be rejected
// 	if a.Authenticate(username, lr.Token) {
// 		t.Fail()
// 	}
// }
