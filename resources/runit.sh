#!/bin/bash
set -x

export ACCESS_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwMDAwMDAwLCJpc3MiOiJ0ZXN0In0.tpfcMVHriGTJvU3RyxgEwIKuao-Q5BYBOgRk-jvduaI
curl -v "https://localhost:8443/blank.html&access_token=$ACCESS_TOKEN"
