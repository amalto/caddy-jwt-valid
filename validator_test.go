package jwtvalid

import (
	"go.uber.org/zap"
	"testing"
	"time"
)

func TestSecret(t *testing.T) {

	t.Log("Testing Secret")

	// This is a token with log expiry
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE5MTAwMDAwMDAsImlzcyI6InRlc3QifQ.JajFc5rZfI5gY4krYaM0i774EKW3dWMoDWm3O8U70RE"
	hasClaims := make(map[string]string)
	hasClaims["foo"] = "bar"
	duration, _ := time.ParseDuration("120s")
	validator := NewValidator("", "AllYourBase", duration, &hasClaims, zap.New(nil))
	valid, err := validator.Valid(token)
	if !valid {
		t.Log(err)
		t.Fail()
	}
}
