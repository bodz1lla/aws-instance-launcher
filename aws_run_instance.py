#!/usr/bin/env python3
import sys
import time
from flask import Flask, request, jsonify
import json, boto3, botocore
import paramiko
import crypt

port = 8080
ami_id = 'ami-dd3c0f36'
instance_type = 't2.micro'
keyname  = 'mykey'
username = 'centos'
pkey_file = '~/.ssh/mykey.pem'

ec2 = boto3.resource('ec2')


class EC2Instance:

    username = None
    password = None

    def create_instance(self, credentials):
        try:
            sg = ec2.create_security_group(Description='My Security Group', GroupName='mysg', DryRun=False)
            sg.authorize_ingress(IpProtocol="tcp",CidrIp="0.0.0.0/0",FromPort=22,ToPort=22)
            print ("Creating AWS Secury Group to allow SSH access...")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "InvalidGroup.Duplicate":
                print ("Security Group already exists.")
                pass
        print ("Creating AWS EC2 instance...")
        data = {}
        instance_id = ec2.create_instances(
                            ImageId = ami_id,
                            MinCount = 1,
                            MaxCount = 1,
                            KeyName = keyname,
                            InstanceType = instance_type,
                        )[0].id
        instance = ec2.Instance(instance_id)
        instance.wait_until_running(Filters=[{'Name': 'instance-state-name', 'Values': ['running',]},],)
        data['instance_id'] = instance_id
        data['instance_ip'] = instance.public_ip_address
        self.ip = data['instance_ip']
        self.username = credentials.get("username")
        self.password = credentials.get("password")
        return self.connect()

    def connect(self):
        key = paramiko.RSAKey.from_private_key_file(pkey_file)
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print ("Connecting to instance...")
        time.sleep(30)
        connect = self.ssh.connect(hostname = self.ip, username = username, pkey = key)
        print ("Connection established. :)")
        return self.adduser()


    def adduser(self,sudo=False):
        shadow_password = crypt.crypt(self.password)
        print("Adding ssh user...")
        command = "sudo useradd -m " + self.username + " -p " + shadow_password
        stdin, stdout, stderr = self.ssh.exec_command(command)
        stdin.flush()
        stdin.channel.shutdown_write()
        ret = stdout.read()
        err = stderr.read()
        print ("The user has been added.")
        return self.allow_access()

    def allow_access(self):
        print ("Allowing ssh access to user...")
        commands  = ["sudo sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config", "sudo systemctl restart sshd"]
        for c in commands:
            stdin, stdout, stderr = self.ssh.exec_command(c)
        print ("Access granted.\n")
        self.ssh.close()
        return self.details()

    def details(self):
        response=json.dumps(self.ip)
        print ("Connection information:\n")
        print("IP:" + self.ip)
        print("Username: " + self.username)
        print("Password: " + self.password+"\n")
        return response


app = Flask(__name__)

@app.route('/create', methods=['POST'])

def main():
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        abort(400)
    credentials = {
        'username': request.json['username'],
        'password': request.json['password'],
    }

    return EC2Instance().create_instance(credentials)
    print ("Try to access and enjoy your day!")

if __name__ == "__main__":
    app.run(port=port, debug=True)
