# AWS Instance Launcher

A python script is launch AWS EC2 instance and creates a new user provided via curl request.


## Getting Started

./aws_run_instance.py
curl -d '{"username":"myuser", "password":"lO7kDyNz64dW"}' -H "Content-Type: application/json" -X POST http://127.0.0.1:8080/create
