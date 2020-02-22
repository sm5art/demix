FROM tensorflow/tensorflow:1.14.0-gpu-py3
RUN apt-get update && apt-get install -y ffmpeg
RUN mkdir /demix
WORKDIR /demix
COPY . .
RUN pip install -r requirements.txt
RUN chmod +x run.sh
ENTRYPOINT ["bash", "run.sh"]