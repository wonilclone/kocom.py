FROM python:3.7.3

ENV LANG C.UTF-8

# Copy data for add-on
COPY run.sh kocom.py kocom_main.py device_parser.py mqtt_handler.py rs485.py logger.py /

# Install requirements for add-on
RUN python3 -m pip install pyserial
RUN python3 -m pip install paho-mqtt
RUN python3 -m pip install typing_extensions

WORKDIR /share

RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
