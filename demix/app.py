from spleeter.separator import Separator
import os
from flask import Flask, flash, request, redirect, url_for
from werkzeug.utils import secure_filename

from demix.config import setup_app_config
from demix.utils.directory import current_directory

ALLOWED_EXTENSIONS = {'mp3'}
IN_FOLDER = current_directory(__file__) + "/raw/in"
OUT_FOLDER = current_directory(__file__) + "/raw/out"
app = Flask(__name__)
setup_app_config(app, IN_FOLDER)
separator = Separator('spleeter:4stems')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        fil = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if fil.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if fil and allowed_file(fil.filename):
            # file succeded
            filename = secure_filename(fil.filename)
            output_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            fil.save(output_file)
            separator.separate_to_file(output_file, OUT_FOLDER)

            return redirect('/')
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

"""
@app.route('/process_song')
def process_song():
    separator.separate_to_file('/path/to/audio', '/path/to/output/directory')
"""
