package jwtvalid

import (
	"go.uber.org/zap"
	"testing"
)

func TestSecret(t *testing.T) {

	t.Log("Testing Secret")

	// This is am expired token
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwMDAwMDAwLCJpc3MiOiJ0ZXN0In0.tpfcMVHriGTJvU3RyxgEwIKuao-Q5BYBOgRk-jvduaI"
	hasClaims := make(map[string]string)
	hasClaims["foo"] = "bar"
	validator := NewValidator("", "AllYourBase", &hasClaims, zap.New(nil))
	valid, err := validator.Valid(token)
	if !valid {
		t.Log(err)
		t.Fail()
	}
}
