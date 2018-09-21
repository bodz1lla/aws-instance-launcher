#!/usr/bin/env python3
import sys
import time
from flask import Flask, request, jsonify, render_template
import json, boto3, botocore
import paramiko
import crypt

DryRun = False;

port = 8080
ami_id = 'ami-dd3c0f36'
instance_name = 'rocket'
environment = 'dev'
instance_type = 't2.micro'
keyname  = 'mykey'
username = 'centos'
pkey_file = '/Users/bogdan.denysiuk/.ssh/mykey.pem'


ec2 = boto3.resource('ec2')
instance = ec2.Instance('id')
client = boto3.client('ec2')
network_interface = ec2.NetworkInterface('id')

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
        ec2_create = ec2.create_instances(
                            BlockDeviceMappings=[
                                {
                                    'DeviceName': 'xvdh',
                                    'Ebs': {
                                        'DeleteOnTermination': True,
                                        #'SnapshotId': '',
                                        'VolumeSize': 8,
                                        'VolumeType': 'gp2',
                                    },
                                },
                            ],
                            ImageId = ami_id,
                            MinCount = 1,
                            MaxCount = 1,
                            KeyName = keyname,
                            InstanceType = instance_type,
                        )
        ec2_create[0].wait_until_running()
        tags = [{
                    "Key" : "Name",
                    "Value" : instance_name
                },
                {
                    "Key" : "Environment",
                    "Value" : environment
                }]
        ec2.create_tags(Resources=[ec2_create[0].id], Tags=tags)
        self.ip = client.describe_instances(DryRun=DryRun, InstanceIds=[ec2_create[0].id])['Reservations'][0]['Instances'][0]['PublicIpAddress']
        self.instance_id = ec2_create[0].id
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
        print ("Connection information:\n")
        print("IP:" + self.ip)
        print("Username: " + self.username)
        print("Password: " + self.password+"\n")
        data = {
            "instance_ip": self.ip,
            "instance_id": self.instance_id
        }
        response = json.dumps(data)
        return response

    def terminate(self, instance_id):
        try:
            print ("Terminating an instance.." +instance_id)
            client.terminate_instances(DryRun=DryRun, InstanceIds=[instance_id])
        except (botocore.exceptions.ClientError, botocore.exceptions.WaiterError) as e:
                print ("The instance ID: " + instance_id + "does not exists.")
                return 'Instance not found.'
                sys.exit(0)
        instance.wait_until_terminated(DryRun=DryRun, InstanceIds=[instance_id])
        print ("Terminated: " +instance_id)
        return self.remove_volume()

    def remove_volume(self):
        for vol in ec2.volumes.all():
           if vol.state == 'available':
               if vol.tags is None:
                   vid = vol.id
                   v   = ec2.Volume(vol.id)
                   v.delete()
                   print ("Deleted " +vid)
                   continue
        return 'OK'

app = Flask(__name__)

@app.route('/')
def readme():
    return render_template('readme.html')

@app.route('/create', methods=['POST'])

def main():
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        abort(400)
    credentials = {
        'username': request.json['username'],
        'password': request.json['password'],
    }
    return EC2Instance().create_instance(credentials)

@app.route('/destroy/<instance_id>', methods=['DELETE'])

def destroy(instance_id):
    return EC2Instance().terminate(instance_id)

if __name__ == "__main__":
    app.run(port=port, debug=True)
