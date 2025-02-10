FROM python:3.10.14

COPY . /app
WORKDIR /app

RUN pip3 install -r requirements.txt
RUN pip3 install -r InfoGrep_BackendSDK/requirements.txt

EXPOSE 4000
CMD ["python3", "main.py"]