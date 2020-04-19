import threading
import queue
import os
from spleeter.separator import Separator
import shutil
import time

from demix.db import ObjectId, get_db
from demix.utils.directory import current_directory

q = queue.Queue()
db = get_db()
def init_seperator(stems=2):
    return Separator('spleeter:%dstems-16kHz' % stems)
separator_2stems = init_seperator()
OUT_FOLDER = os.path.abspath(os.path.join(current_directory(__file__))) + "/raw/out"
seperator_4stems = init_seperator(stems=4)
POLL_PERIOD = 0.01 # sleep amount in s between polls

def thread_main():
    while True:
        if not q.empty():
            item = q.get()
            db.uploaded_file.update_many({"processed": False, "queue": { "$gt": 0} }, {"$inc": { "queue": -1 }})
            data_id = item['_id']
            output_file = item['local_filename']
            folder = item['processed_output']
            stems = item['stems']
            try:
                if stems == 4:
                    seperator_4stems.separate_to_file(output_file, OUT_FOLDER, bitrate='128k')
                else:
                    separator_2stems.separate_to_file(output_file, OUT_FOLDER, bitrate='128k')
                shutil.make_archive(folder, 'zip', folder)
            except Exception as e:
                pass
            db.uploaded_file.update_one({'_id': ObjectId(data_id)}, {"$set":{ "processed": True }})
        time.sleep(POLL_PERIOD)

t = threading.Thread(target=thread_main)
t.start()

def enqueue(item):
    q.put(item)
    return queue_size()

def queue_size():
    return q.qsize()

