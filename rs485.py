"""
rs485.py
- RS485Wrapper: 시리얼/소켓 연결
- send_packet: Kocom 프로토콜 전송 & ACK 대기
"""
import time
import logging
import random
import socket
import platform
import queue
import serial

from device_parser import (
    READ_WRITE_GAP, HEADER_HEX, TRAILER_HEX, checksum, TYPE_NAME_TO_HEX
)


class RS485Wrapper:
    def __init__(self, serial_port=None, socket_server=None, socket_port=0):
        self.conn = None
        self.serial_port = serial_port
        self.socket_server = socket_server
        self.socket_port = socket_port
        if socket_server:
            self.type = 'socket'
        else:
            self.type = 'serial'
        self.last_read_time = 0

    def connect(self):
        self.close()
        self.last_read_time = 0
        if self.type=='serial':
            self.conn = self._connect_serial()
        else:
            self.conn = self._connect_socket()
        return self.conn

    def _connect_serial(self):
        if not self.serial_port:
            if platform.system()=='Linux':
                self.serial_port = '/dev/ttyUSB0'
            else:
                self.serial_port = 'COM3'
        try:
            ser = serial.Serial(self.serial_port, 9600, timeout=1)
            ser.bytesize = 8
            ser.stopbits = 1
            if not ser.is_open:
                raise Exception('Serial not open')
            logging.info(f'[RS485] Serial connected: {ser}')
            return ser
        except Exception as e:
            logging.error(f'[RS485] Serial open failure: {e}')
            return False

    def _connect_socket(self):
        sock = socket.socket()
        sock.settimeout(10)
        try:
            sock.connect((self.socket_server, self.socket_port))
        except Exception as e:
            logging.error(f'[RS485] Socket connect fail: {e}')
            return False
        logging.info(f'[RS485] Socket connected: {self.socket_server}:{self.socket_port}')
        sock.settimeout(315)  # polling_interval(300)+15
        return sock

    def read(self):
        if not self.conn:
            return b''
        ret = b''

        for _ in range(315):
            try:
                if self.type=='serial':
                    r = self.conn.read()
                else:
                    r = self.conn.recv(1)
                if r:
                    ret = r
                    break
            except Exception as e:
                raise Exception(f"read error: {e}")

        if not ret:
            raise Exception('read byte error or timeout')
        self.last_read_time = time.time()
        return ret

    def write(self, data: bytes):
        if not self.conn:
            return False
        if self.last_read_time==0:
            time.sleep(1)
        while (time.time()-self.last_read_time)<READ_WRITE_GAP:
            time.sleep(0.01)

        if self.type=='serial':
            return self.conn.write(data)
        else:
            return self.conn.send(data)

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except:
                pass
            self.conn = None

    def reconnect(self):
        self.close()
        while True:
            logging.info('[RS485] reconnecting...')
            if self.connect():
                break
            time.sleep(10)
