package jwtvalid

import (
	"go.uber.org/zap"
	"testing"
	"time"
)

func TestSecret(t *testing.T) {

	t.Log("Testing Secret")

	// This is a token with log expiry
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE5MTAwMDAwMDAsImlzcyI6Imh0dHA6Ly9hbWFsdG8uY29tIiwic3ViIjoiZGVmYXVsdCIsImF1ZCI6WyJkZWZhdWx0Il0sIm5iZiI6MTYwMzcwNjI1MSwiaWF0IjoxNjAzNzA2MjUxLCJqdGkiOiJiMmp3dC0xLjAuMSIsInR5cCI6IkpXVCIsImh0dHA6Ly9hbWFsdG8uY29tL3JlYWxtIjoiYjIiLCJodHRwOi8vYW1hbHRvLmNvbS91c2VyX2VtYWlsIjoiYWRtaW5AYW1hbHRvLmNvbSJ9.keNIEqY8NNbHBH4Iwo_J0TecrUoR218weTi2PxEl9Ho"
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
