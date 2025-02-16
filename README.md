# aws-cloudshell-starter

This is a starter project for AWS CloudShell.
It includes a simple go application that generates command to connect AWS CloudShell session.

## usage
* Install awscli and session-manager-plugin.
* Build the go application.
* Run.

```shell
$ eval $(AWS_PROFILE=target ./aws-cloudshell-starter)

Starting session with SessionId: 173968xxxxxx1191682-utrexample366dg8ozjf2urin8
~ $ whoami
cloudshell-user
```

references: https://github.com/iann0036/vscode-aws-cloudshell
