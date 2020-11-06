# Module jwt_valid

```
{
    "pem_keypath": "",
    "secret": "",
    "has_claim": "" "",
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

## Example
____

```
jwt_valid {
  secret "MyBigSecret"
  has_claim foo bar
  has_claim hello world
}
```
