package jwtvalid

import (
	"fmt"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"time"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("jwt_valid", parseCaddyFileJwtValid)
}

func parseCaddyFileJwtValid(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var valid JwtValid
	valid.ClockSkewSeconds = 0
	valid.Claims = make(map[string]string)
	valid.Headers = make(map[string]string)
	for h.Next() {
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			rootDirective := h.Val()
			switch rootDirective {
			case "pem_keypath":
				args := h.RemainingArgs()
				err := singleArgumentCheck(rootDirective, args)
				if err != nil {
					return nil, err
				}
				valid.KeyPath = args[0]
			case "secret":
				args := h.RemainingArgs()
				err := singleArgumentCheck(rootDirective, args)
				if err != nil {
					return nil, err
				}
				valid.Secret = args[0]
			case "clockskew":
				args := h.RemainingArgs()
				err := singleArgumentCheck(rootDirective, args)
				if err != nil {
					return nil, err
				}
				valid.ClockSkewSeconds, err = time.ParseDuration(args[0])
				if err != nil {
					return nil, err
				}
				if valid.ClockSkewSeconds < 0 {
					return nil, fmt.Errorf("invalid clockskew value less than zero")
				}
			case "has_claim":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) != 2 {
					return nil, fmt.Errorf("%s argument value of %s is unsupported", rootDirective, args[0])
				}
				valid.Claims[args[0]] = args[1]
			case "fail_header":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) != 2 {
					return nil, fmt.Errorf("%s argument value of %s is unsupported", rootDirective, args[0])
				}
				valid.Headers[args[0]] = args[1]
			}
		}
	}
	if len(valid.KeyPath) == 0 && len(valid.Secret) == 0 {
		return nil, fmt.Errorf("argument count mismatch.  keypath or secret must be supplied")
	}
	return valid, nil
}

func singleArgumentCheck(directive string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s argument has no value", directive)
	}
	if len(args) != 1 {
		return fmt.Errorf("%s argument value of %s is unsupported", directive, args[0])
	}
	return nil
}
