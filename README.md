# demix

## Installation
1. Install Python 3.6/3.7 and virtualenv
2. Install Docker CE
3. Install Node.js
4. ```sudo npm install -g gatsby-cli```
5. git clone demix-frontend in the parent directory of demix s.t. ../demix-frontend/ is the path to the git repo
6. cd into demix-frontend and run ```npm install```
7. art will give you some secret files: place demix.cfg into the folder demix where app.py is, and nginx.crt/nginx.key should go in the root of the repo


## Setup for local deployment
Build the latest frontend and then deploy with docker
1. ```./build_bundle.sh```
2. ```./docker_build.sh```
3. ```./docker_run.sh```
Go to https://localhost to see a local deployment

## Run local dev server
0. get mongodb installed and running locally (optional)
1. ```virtualenv venv```
2. ```. venv/bin/activate```
3. ```pip install -r requirements.txt```
4. ./dev_run.sh 
api server now running at :5000
Go to demix-frontend readme and follow instructions on setting up frontend dev server
