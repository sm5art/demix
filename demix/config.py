import configparser
import os
from demix.utils.directory import current_directory

CONFIG = current_directory(__file__) + "/demix.cfg"

def get_cfg(section):
    config = configparser.ConfigParser()
    config.read(CONFIG)
    api = config.items(section)
    return dict(api)