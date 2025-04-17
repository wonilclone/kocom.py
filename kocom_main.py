"""
kocom_main.py
메인 실행부: 설정 로드, RS485 초기화, MQTT 초기화, 스레드 구동, Discovery 등
순환참조를 피하기 위해 AppContext를 만들어 필요한 자원을 담고,
각 함수/모듈에 context를 인수로 넘기는 방식을 사용.
"""
import configparser
import queue
import signal
import threading
import time

import logger
from device_parser import (
    BUF_SIZE,
    CHECKSUM_POSITION,
    CONFIG_FILE,
    DEVICE_NAME_TO_HEX,
    HEADER_HEX,
    PACKET_SIZE,
    ROOM_NAME_TO_HEX,
    TRAILER_HEX,
    checksum,
    parse_packet,
    publish_status,
    query_device,
)
from mqtt_handler import discovery, init_mqtt_client
from rs485 import RS485Wrapper

# ======================== AppContext 정의 =========================

class AppContext:
    """
    프로그램 전체에서 공유될 자원(설정, 큐, RS485, MQTT 클라이언트, 락 등)을 담는 컨테이너
    """
    def __init__(self):
        self.config = None
        self.rs485 = None
        self.mqtt_client = None

        self.msg_queue = None
        self.ack_queue = None
        self.ack_data_list = None
        self.wait_queue = None
        self.wait_target = None
        self.send_lock = None

        self.cache_data = None
        self.thread_list = None
        self.poll_timer = None

        # poll_state를 다른 곳(mqtt_on_message 등)에서 부르고 싶을 때
        # 순환참조 없이 함수 레퍼런스를 저장해둠
        self.poll_state_cb = None


# ======================== 스레드 함수 =========================

def read_serial(context: AppContext):
    """
    RS485에서 1바이트씩 읽어, 헤더~트레일러(21바이트)까지 버퍼링 후 msg_queue에 전달
    """
    buffer_hex = ''
    leftover_hex = ''

    while True:
        try:
            # 1바이트씩 16진수로 변환
            buffer_hex += f"{context.rs485.read()[0]:02x}"

            # 헤더 검사
            if buffer_hex[:len(HEADER_HEX)] != HEADER_HEX[:len(buffer_hex)]:
                leftover_hex += buffer_hex
                buffer_hex = ''
                frame_start = leftover_hex.find(HEADER_HEX, len(HEADER_HEX))
                if frame_start < 0:
                    continue
                else:
                    leftover_hex = leftover_hex[:frame_start]
                    buffer_hex = leftover_hex[frame_start:]

            if leftover_hex:
                logger.log_info('[comm] leftover not parsed: ' + leftover_hex)
                leftover_hex = ''

            if len(buffer_hex) == (PACKET_SIZE * 2):
                # 체크섬 검사
                calc_sum = checksum(buffer_hex[len(HEADER_HEX):CHECKSUM_POSITION*2])
                recv_sum = buffer_hex[CHECKSUM_POSITION*2 : CHECKSUM_POSITION*2+2]
                if calc_sum == recv_sum and buffer_hex[-4:] == TRAILER_HEX:
                    # 유효 패킷
                    if not context.msg_queue.full():
                        context.msg_queue.put(buffer_hex)
                    else:
                        logger.log_error('msg_queue is full. listen_hex thread may be blocked.')
                    buffer_hex = ''
                else:
                    logger.log_info(f"[comm] invalid packet {buffer_hex}, expected={calc_sum}")
                    frame_start = buffer_hex.find(HEADER_HEX, len(HEADER_HEX))
                    if frame_start < 0:
                        leftover_hex += buffer_hex
                        buffer_hex = ''
                    else:
                        leftover_hex += buffer_hex[:frame_start]
                        buffer_hex = buffer_hex[frame_start:]

        except Exception as ex:
            logger.log_error(f"*** read_serial error: {ex}")
            context.poll_timer.cancel()
            context.cache_data.clear()
            context.rs485.reconnect()
            context.poll_timer = threading.Timer(2, context.poll_state_cb, args=(context, False))
            context.poll_timer.start()


def listen_hex(context: AppContext):
    """
    msg_queue에서 패킷을 꺼내 parse 후,
    - ACK 확인
    - wait_target 중인 목적지 확인
    - 그 외는 publish_status()
    """

    while True:
        hex_data = context.msg_queue.get()

        if context.config.getboolean('Log', 'show_recv_hex', fallback=False):
            logger.log_info("[recv] " + hex_data)

        packet_obj = parse_packet(hex_data)
        context.cache_data.insert(0, packet_obj)
        if len(context.cache_data) > BUF_SIZE:
            context.cache_data.pop()

        # ACK 확인
        if packet_obj.data_hex in context.ack_data_list:
            context.ack_queue.put(hex_data)
            continue

        # send_wait_response 대기중?
        if not context.wait_target.empty():
            current_target = context.wait_target.queue[0]
            if packet_obj.dest_hex == current_target and packet_obj.type_name == 'ack':
                if len(context.ack_data_list) != 0:
                    logger.log_info("[ACK] No ack received, but response arrived first. Accepting as ack.")
                    context.ack_queue.put(hex_data)
                time.sleep(0.3)
                context.wait_queue.put(packet_obj)
                continue

        # 그 외는 MQTT로 publish
        publish_status(context, packet_obj)


# ======================== poll_state (주기 폴링) =========================

def poll_state(context: AppContext, enforce=False):
    if context.poll_timer:
        context.poll_timer.cancel()


    dev_list = [x.strip() for x in context.config.get('Device','enabled',fallback='').split(',')]
    no_polling_list = ['wallpad','elevator']

    for th in context.thread_list:
        if not th.is_alive():
            logger.log_error(f'[THREAD] {th.name} is not active. restarting...')
            th.start()

    for dev_str in dev_list:
        parts = dev_str.split('_')
        dev_type = parts[0]
        if dev_type in no_polling_list:
            continue
        dev_hex = DEVICE_NAME_TO_HEX.get(dev_type)
        if len(parts) > 1:
            sub_hex = ROOM_NAME_TO_HEX.get(parts[1], '00')
        else:
            sub_hex = '00'

        if dev_hex:
            full_id = dev_hex + sub_hex
            pkt = query_device(context, full_id, publish=True, enforce=enforce)
            if pkt.flag is False:
                break
            time.sleep(1)

    context.poll_timer = threading.Timer(300, poll_state, args=(context,))
    context.poll_timer.start()


# ======================== 메인 실행부 =========================

def main():
    logger.set_log_level('DEBUG')
    context = AppContext()

    # 설정 로드
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    context.config = config

    # RS485
    r_type = config.get('RS485','type')
    if r_type == 'serial':
        ser_port = config.get('RS485','serial_port', fallback=None)
        context.rs485 = RS485Wrapper(serial_port=ser_port)
    else:
        srv = config.get('RS485','socket_server')
        prt = int(config.get('RS485','socket_port'))
        context.rs485 = RS485Wrapper(socket_server=srv, socket_port=prt)

    if not context.rs485.connect():
        logger.log_error('[RS485] connection error. exit')
        return

    # MQTT
    context.mqtt_client = init_mqtt_client(context)

    if not context.mqtt_client:
        logger.log_error('[MQTT] connection error. exit')
        return

    # 큐, 락, 타이머 등
    context.msg_queue = queue.Queue(BUF_SIZE)
    context.ack_queue = queue.Queue(1)
    context.ack_data_list = []
    context.wait_queue = queue.Queue(1)
    context.wait_target = queue.Queue(1)
    context.send_lock = threading.Lock()
    context.cache_data = []
    context.thread_list = []
    context.poll_timer = None

    # poll_state를 콜백으로 저장 → mqtt 등에서 context.poll_state_cb(context, True) 호출 가능
    context.poll_state_cb = poll_state

    # 스레드
    read_serial_thread = threading.Thread(target=read_serial, args=(context,), name='read_serial')
    listen_hex_thread = threading.Thread(target=listen_hex, args=(context,), name='listen_hex')
    context.thread_list.extend([read_serial_thread, listen_hex_thread])

    for thread in context.thread_list:
        thread.start()

    # 폴링 시작
    context.poll_timer = threading.Timer(1, poll_state, args=(context, False))
    context.poll_timer.start()

    # MQTT Discovery
    discovery(context)

    # 메인 스레드는 대기
    signal.sigwait((signal.SIGINT, signal.SIGTERM))


if __name__ == "__main__":
    main()
