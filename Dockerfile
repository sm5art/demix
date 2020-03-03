FROM tensorflow/tensorflow:1.14.0-py3
RUN apt-get update && apt-get install -y ffmpeg nginx
RUN mkdir /demix
WORKDIR /demix
COPY . .
COPY nginx.conf /etc/nginx/nginx.conf
COPY public /www/data
COPY nginx.crt /etc/ssl/certs/nginx.crt
COPY nginx.key /etc/ssl/private/nginx.key
RUN pip install -r requirements.txt

# Define mountable directories.
# Define working directory.
# Define default command.
RUN chmod +x run.sh
ENTRYPOINT ["bash", "run.sh"]