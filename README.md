# aws-cloudshell-starter
Connecting to AWS CloudShell from your terminal using AWS Systems Manager Session Manager.

## usage
* Install awscli and session-manager-plugin.
* Build the go application.
* Run.

### Non-VPC environment
```shell
$ AWS_PROFILE=target ./aws-cloudshell-starter
...
Starting session with SessionId: 173968xxxxxx1191682-utrexample366dg8ozjf2urin8
~ $ echo Hello CloudShell!
Hello CloudShell!
~ $ whoami
cloudshell-user
```

### VPC environment
```shell
$ AWS_PROFILE=target ./aws-cloudshell-starter -vpc-id vpc-xxxx -subnet-ids subnet-xxxx,subnet-yyyy -security-group-ids sg-xxxx,sg-yyyy,sg-zzzz
...
Starting session with SessionId: 174017xxxxxx5437987-4fzjq9yipyritexamp1e9ycnda
~ $ echo Hello CloudShell!
Hello CloudShell!
~ $ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:3d:c0:1b:68 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: ens7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 0e:0b:fe:92:5f:fb brd ff:ff:ff:ff:ff:ff
    altname enp0s7
    altname eni-0ade5ecexamp1ef96
    altname device-number-2.0
    inet 10.35.255.180/26 scope global ens7
       valid_lft forever preferred_lft forever
7: devfile-veth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether de:59:33:ea:52:8d brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.0.2/32 scope global devfile-veth0
       valid_lft forever preferred_lft forever
```

### Custom initialization script
You can use the `-init-script` option to specify a custom initialization script.
This script will be executed in the CloudShell session.

```shell
$ AWS_PROFILE=target ./aws-cloudshell-starter -init-script ./init.sh
...
Starting session with SessionId: 1740296564950814169-cpkoexAmp1Epxls74bbvzxe9h4
~ $ source <(curl -s -H 'x-amz-server-side-encryption-customer-key: OBYg97D3+5ExamPLeI/7WRry4uOyeXaMp1e+JsKirnI=' 'https://...(presigned url)...') 
Hello custom CloudShell!
AWS Account ID: 1234567890XX
IP Address: xx.xx.xx.xx
cloudshell-user@ip-xx-xx-xx-xx:~$ 

```

#### example: mount s3 bucket
You can mount s3 bucket using `mount-s3` command in initialization script.
```shell
# mount s3
sudo yum -y -q install https://s3.amazonaws.com/mountpoint-s3-release/latest/x86_64/mount-s3.rpm
sudo mkdir -p /mnt/work
sudo chown cloudshell-user. /mnt/work
mount-s3 <<target-bucket>> /mnt/work --allow-delete
cd /mnt/work

```

references: https://github.com/iann0036/vscode-aws-cloudshell
