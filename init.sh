#!/bin/bash

# custom setup script
echo "Hello custom CloudShell!"
echo "AWS Account ID: $(aws sts get-caller-identity | jq -r .Account)"
echo "IP Address: $(curl -s checkip.amazonaws.com)"

export PS1="\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "