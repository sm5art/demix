# demix

## Installation
1. ```mkdir -p demix/raw/in && mkdir demix/raw/out ```
2. ```virtualenv venv```
3. ```. venv/bin/activate```
4. ```pip install -r requirements.txt```

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