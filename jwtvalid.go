package jwtvalid

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

func init() {
	caddy.RegisterModule(JwtValid{})
}

type JwtValid struct {
	KeyPath          string            `json:"pemkeypath,omitempty"`
	Secret           string            `json:"secret,omitempty"`
	Claims           map[string]string `json:"hasclaims,omitempty"`
	ClockSkewSeconds time.Duration     `json:"clockskew,omitempty"`

	logger    *zap.Logger
	validator *Validator
}

func (JwtValid) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jwt_valid",
		New: func() caddy.Module { return new(JwtValid) },
	}
}

func (jtv *JwtValid) Provision(ctx caddy.Context) error {
	jtv.logger = ctx.Logger(jtv)
	jtv.validator = NewValidator(jtv.KeyPath, jtv.Secret, jtv.ClockSkewSeconds, &jtv.Claims, jtv.logger)
	return nil
}

func (jtv JwtValid) ServeHTTP(resp http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	var err error
	if req.Method != "OPTIONS" {
		token := req.URL.Query().Get("access_token")
		if len(token) == 0 {
			token = extractTokenFromHeader(req)
		}
		if len(token) == 0 {
			err = fmt.Errorf("jwt not found")
			jtv.logger.Warn("no jwt", zap.Error(err))
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
		validJwt, err := jtv.validator.Valid(token)
		if !validJwt || err != nil {
			if err != nil {
				err = fmt.Errorf("invalid request jwt %v", err)
			} else {
				err = fmt.Errorf("invalid request jwt")
			}
			jtv.logger.Warn("invalid jwt", zap.Error(err))
			return caddyhttp.Error(http.StatusUnauthorized, err)
		}
	}
	return next.ServeHTTP(resp, req)
}

func extractTokenFromHeader(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearerToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*JwtValid)(nil)
