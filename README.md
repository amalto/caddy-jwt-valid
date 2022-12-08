# Module jwt_valid

```
{
    "pem_keypath": "",
    "secret": "",
    "has_claim": "" "",
    "startswith_claim": "" "",
    "clockskew": "",
    "fail_header": "" ""
}
```
## Description
____

An HTTP middleware module that validates a JWT using the given query parameter `access_token` or `Authorization` header. 

_It will skip validation if the current HTTP request is an OPTIONS call_

Validation can be performed using a given `secret` OR a public key provided in a PEM formatted file

## Field List
____

**pem_keypath**
  
Path to PEM formatted public key file

**secret**

A text string containing a secret

**has_claim**

Optional additional validation to ensure given claims contain given values

Expressed as _[name] [value]_ pairs

This field can repeat

**startswith_claim**

Optional additional validation to ensure given claims starts with the given values

Expressed as _[name] [value]_ pairs

This field can repeat

**clockskew**

Optional time offset to be used to extend the token expiry validation range

Expressed as a string suitable for https://golang.org/pkg/time/#ParseDuration

**fail_header**

Optional additional HTTP headers to add to any failed response

Expressed as _[name] [value]_ pairs

## Example
____

```
jwt_valid {
  secret "MyBigSecret"
  has_claim foo bar
  startswith_claim foo ba
  has_claim hello world
  clockskew "10m"
  fail_header hello world
}
```

### Build Instructions

The Makefile is used for all build operations.  The file `envfile` is used for local environment customisations.

Please refer to https://caddyserver.com/docs/extending-caddy for details of configuring your environment and the use of `xcaddy`.
__________

The current version of Caddy Server specified in the envfile is **2.6.2** 

__________
