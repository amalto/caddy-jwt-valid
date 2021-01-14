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
	Headers          map[string]string `json:"failheaders,omitempty"`
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

	if req.Method != "OPTIONS" {
		token := req.URL.Query().Get("access_token")
		if len(token) == 0 {
			token = extractTokenFromHeader(req)
		}
		if len(token) == 0 {
			jtv.writeUnauthorizedResponse(resp, fmt.Errorf("bearer authentication token not found"))
		} else {
			validJwt, err := jtv.validator.Valid(token)
			if !validJwt || err != nil {
				if err != nil {
					err = fmt.Errorf("failed token verification %v", err)
				} else {
					err = fmt.Errorf("failed token verification")
				}
				jtv.writeUnauthorizedResponse(resp, err)
			}
		}
	}
	return next.ServeHTTP(resp, req)
}

func (jtv JwtValid) writeUnauthorizedResponse(resp http.ResponseWriter, err error) {
	jtv.logger.Warn("jwt issue", zap.Error(err))
	for key, value := range jtv.Headers {
		resp.Header().Add(key, value)
	}
	resp.WriteHeader(http.StatusUnauthorized)
	_, wErr := resp.Write([]byte(err.Error()))
	if nil != wErr {
		jtv.logger.Fatal("response write failure", zap.Error(wErr))
	}
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
