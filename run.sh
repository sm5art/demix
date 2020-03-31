export FLASK_APP=demix/app.py
nginx
while true
do
flask run --host=0.0.0.0
sleep 1
done