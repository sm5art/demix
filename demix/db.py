from pymongo import MongoClient

from demix.config import get_cfg

cfg = get_cfg('mongo')

def get_db():
    client = MongoClient(cfg['db_url']).demix
    return client