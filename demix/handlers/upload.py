from flask import Blueprint, request, jsonify, send_file
import re # for filename parsing see below
import shutil # for zipping
from spleeter.separator import Separator
from werkzeug.utils import secure_filename
import datetime
import hashlib
import os
import os.path
import pathlib

from demix.utils.logging import logger_factory
from demix.utils.flask import current_user, protected, custom_error
from demix.db import get_db, ObjectId
from demix.utils.directory import current_directory

ALLOWED_EXTENSIONS = {'mp3', 'wav'}
MAX_FREE_FILE_UPLOADS = 3
IN_FOLDER = os.path.abspath(os.path.join(current_directory(__file__), os.pardir)) + "/raw/in"
OUT_FOLDER = os.path.abspath(os.path.join(current_directory(__file__), os.pardir)) + "/raw/out"

# create directories if they do not exist on startup
pathlib.Path(IN_FOLDER).mkdir(parents=True, exist_ok=True)
pathlib.Path(OUT_FOLDER).mkdir(parents=True, exist_ok=True)

extract_filename_pattern = re.compile(r'(.+?)\.[^.]*$|$')
def init_seperator(stems=2):
    return Separator('spleeter:%dstems-16kHz' % stems)
separator_2stems = init_seperator()
seperator_4stems = init_seperator(stems=4)
upload = Blueprint('upload', __name__,)
logger = logger_factory(__name__)
db = get_db()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file_error():   
    return custom_error('file incorrect')    

def get_file_count_for_user_id(user_id):
    val = db.uploaded_file.count({'user_id': user_id, 'datetime': {'$gt': datetime.datetime.now() - datetime.timedelta(days=1)}})
    logger.info(val)
    return val

@upload.route('/api/file_count')
@protected
def file_count():
    user = current_user()
    return jsonify({"data": get_file_count_for_user_id(user['_id'])})


@upload.route('/api/post_file', methods=['POST'])
@protected
def upload_file():
    # check if the post request has the file part
    if 'file' not in request.files:
        return upload_file_error()
    fil = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if fil.filename == '':
        return upload_file_error()
    if fil and allowed_file(fil.filename):
        # file succeded
        user = current_user()
        user_id = user['_id']
        stems = request.form.get('stems', type=int)
        if stems not in [2, 4]:
            stems = 2
        logger.info("=====USER UPLOADED=====")
        logger.info(user)
        if get_file_count_for_user_id(user_id) >= MAX_FREE_FILE_UPLOADS:
            logger.info("reached limit")
            return custom_error("reached file upload limit")
        filename = secure_filename(fil.filename)
        content = fil.read()
        md5 = hashlib.md5(content).hexdigest()
        safe_filename = md5+str(user_id)+str(stems)
        folder = '%s/%s' % (OUT_FOLDER, safe_filename)
        output_file = os.path.join(IN_FOLDER, safe_filename)
        logger.info("NAME of file: "+ filename)
        logger.info('OUTFOLDER: %s' % folder)
        existing_files = db.uploaded_file.find_one({"user_id": user_id, "md5": md5, "stems": stems})
        if existing_files is not None:
            logger.info("File already uploaded %s" % str(existing_files))
            return custom_error("file already uploaded")
        with open(output_file, 'wb') as f:
            f.write(content)
        data={
            "secure_filename": filename, 
            "datetime": datetime.datetime.now(),
            "local_filename": output_file,
            "processed_output": folder,
            "user_id": user_id,
            "loading": True,
            "md5": md5,
            "stems": stems
        }
        data_id = db.uploaded_file.insert_one(data).inserted_id
        if stems == 4:
            seperator_4stems.separate_to_file(output_file, OUT_FOLDER, bitrate='128k')
        else:
            separator_2stems.separate_to_file(output_file, OUT_FOLDER, bitrate='128k')
        db.uploaded_file.update_one({'_id': ObjectId(data_id)}, {"$set":{ "loading": False }})
        shutil.make_archive(folder, 'zip', folder)
        return jsonify({"data" : {"data_id": str(data_id)}})
    return upload_file_error()

@upload.route('/api/result/<result_id>')
def get_result(result_id):
    result = db.uploaded_file.find_one({"_id": ObjectId(result_id)})
    folder = result['processed_output']
    return send_file("%s.zip" % folder)

@upload.route('/api/files', methods=['GET'])
@protected
def get_files():
    user = current_user()
    uploaded_files = list(db.uploaded_file.find({"user_id": user["_id"]}))
    uploaded_files.reverse()
    return jsonify({
        "data": list(map(lambda x: {"_id": str(x['_id']), "filename": x['secure_filename'], "date": x['datetime'], "stems": x['stems'], "loading": x['loading']}, uploaded_files))
    })