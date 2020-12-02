#!/bin/bash
set -x

export ACCESS_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE5MTAwMDAwMDAsImlzcyI6InRlc3QifQ.JajFc5rZfI5gY4krYaM0i774EKW3dWMoDWm3O8U70RE
curl -v "https://localhost:8443/blank.html?access_token=$ACCESS_TOKEN"
