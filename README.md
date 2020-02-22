# demix

## Installation
0. get mongodb installed and running locally
1. ```mkdir -p demix/raw/in && mkdir demix/raw/out ```
2. ```virtualenv venv```
3. ```. venv/bin/activate```
4. ```pip install -r requirements.txt```


FOR NVIDIA DOCKER
1. install docker CE
2. install docker compose
3. install nvidia docker
4. ```docker-compose up```

## Run
```./run.sh``` at root

## Config
```
[mongo]
db_url=...

[google]
client_id=...
client_secret=...

[jwt]
secret=...

```