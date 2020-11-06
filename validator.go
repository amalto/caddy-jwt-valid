package jwtvalid

import (
	"crypto/rsa"
	"fmt"
	jwtlib "github.com/dgrijalva/jwt-go"
	"github.com/spf13/cast"
	"go.uber.org/zap"
	"io/ioutil"
)

type Validator struct {
	logger    *zap.Logger
	publicPEM []byte
	publicKey *rsa.PublicKey
	secret    string
	hasClaims *map[string]string
}

func NewValidator(pemFilePath string, secret string, hasClaims *map[string]string, logger *zap.Logger) *Validator {
	var err error
	v := new(Validator)
	v.logger = logger
	v.hasClaims = hasClaims
	v.secret = secret
	if len(pemFilePath) > 0 {
		v.publicPEM, err = ioutil.ReadFile(pemFilePath)
		if err != nil {
			logger.Error("PEM file read failure", zap.Error(err), zap.String("PEMFilePath", pemFilePath))
			panic(err.Error())
		}
	}
	logger.Info("JWT Validator initialised.")
	return v
}

func (v Validator) Valid(token string) (bool, error) {
	jwtToken, err := jwtlib.Parse(token, v.provideKey)
	if err != nil {
		v.logger.Debug("token validation failed", zap.Error(err))
		return false, err
	}
	// Validate custom claims
	if claims, ok := jwtToken.Claims.(jwtlib.MapClaims); ok && jwtToken.Valid {
		for key, value := range *v.hasClaims {
			claimValue := cast.ToString(claims[key])
			if claimValue != value {
				return false, fmt.Errorf("invalid jwt claim encountered: %s, expected: %s, found: %s", key, value, claimValue)
			}
		}
	}
	v.logger.Debug("token validation successful")

	return true, nil
}

func (v Validator) provideKey(_ *jwtlib.Token) (interface{}, error) {
	var err error
	if len(v.publicPEM) > 0 {
		if v.publicKey == nil {
			v.publicKey, err = jwtlib.ParseRSAPublicKeyFromPEM(v.publicPEM)
		}
		return v.publicKey, err
	} else if len(v.secret) > 0 {
		return []byte(v.secret), nil
	} else {
		return nil, fmt.Errorf("failed to find jwt key")
	}
}
