"""
device_parser.py
- Kocom 패킷 관련 상수/딕셔너리
- KocomPacket 클래스
- parse_packet 함수
- 기기별 상태 파싱 (thermo_parse, ac_parse, ...)
- query_device, send_wait_response (context 인자를 받아 사용)
"""
import json
import queue
import random
import time

import logger

SW_VERSION = '2025.03.28'
CONFIG_FILE = 'kocom.conf'
BUF_SIZE = 100

READ_WRITE_GAP = 0.03
POLLING_INTERVAL = 300

HEADER_HEX = 'aa55'
TRAILER_HEX = '0d0d'
PACKET_SIZE = 21
CHECKSUM_POSITION = 18


# -------------- Hex <-> Name 매핑 --------------
TYPE_HEX_TO_NAME = {'30b': 'send', '30d': 'ack'}
SEQ_HEX_TO_NUM   = {'c':1, 'd':2, 'e':3, 'f':4}
DEVICE_HEX_TO_NAME = {
    '01':'wallpad', '0e':'light','2c':'gas','36':'thermo','39':'ac',
    '3b':'plug','44':'elevator','48':'fan','98':'air'
}
CMD_HEX_TO_NAME = {'00':'state','01':'on','02':'off','3a':'query'}
ROOM_HEX_TO_NAME = {
    '00':'livingroom','01':'room1','02':'room2','03':'room3','04':'kitchen','05':'hallway'
}


TYPE_NAME_TO_HEX = {v:k for k,v in TYPE_HEX_TO_NAME.items()}
DEVICE_NAME_TO_HEX = {v:k for k,v in DEVICE_HEX_TO_NAME.items()}
CMD_NAME_TO_HEX = {v:k for k,v in CMD_HEX_TO_NAME.items()}
ROOM_NAME_TO_HEX = {
    'livingroom':'00','myhome':'00','room1':'01','room2':'02',
    'room3':'03','kitchen':'04','hallway':'05'
}

# -------------- Packet 클래스 --------------

class KocomPacket:
    def __init__(self):
        self.header_hex  = ''
        self.type_hex    = ''
        self.seq_hex     = ''
        self.monitor_hex = ''
        self.dest_hex    = ''
        self.src_hex     = ''
        self.cmd_hex     = ''
        self.value_hex   = ''
        self.checksum_hex= ''
        self.trailer_hex = ''

        self.data_hex    = ''  # type+seq+...+value
        self.payload_hex = ''
        self.type_name   = None
        self.seq_num     = None
        self.dest_name   = None
        self.dest_subid  = None
        self.dest_room   = None
        self.src_name    = None
        self.src_subid   = None
        self.src_room    = None
        self.cmd_name    = None
        self.value       = ''
        self.time        = time.time()
        self.flag        = None

    def __repr__(self):
        return f"<KocomPacket type={self.type_name}, cmd={self.cmd_name}, src={self.src_name}, dest={self.dest_name}>"

# -------------- 체크섬 --------------
def checksum(data_hex: str) -> str:
    s = sum(bytearray.fromhex(data_hex))
    return f"{s % 256:02x}"

# -------------- parse_packet (기존 parse()) --------------
def parse_packet(hex_data: str) -> KocomPacket:
    pkt = KocomPacket()

    pkt.header_hex  = hex_data[:4]
    pkt.type_hex    = hex_data[4:7]
    pkt.seq_hex     = hex_data[7:8]
    pkt.monitor_hex = hex_data[8:10]
    pkt.dest_hex    = hex_data[10:14]
    pkt.src_hex     = hex_data[14:18]
    pkt.cmd_hex     = hex_data[18:20]
    pkt.value_hex   = hex_data[20:36]
    pkt.checksum_hex= hex_data[36:38]
    pkt.trailer_hex = hex_data[38:42]

    pkt.data_hex    = hex_data[4:36]
    pkt.payload_hex = hex_data[18:36]

    pkt.type_name   = TYPE_HEX_TO_NAME.get(pkt.type_hex)
    pkt.seq_num     = SEQ_HEX_TO_NUM.get(pkt.seq_hex)
    pkt.dest_name   = DEVICE_HEX_TO_NAME.get(pkt.dest_hex[:2])
    pkt.dest_subid  = str(int(pkt.dest_hex[2:4],16))
    pkt.dest_room   = ROOM_HEX_TO_NAME.get(pkt.dest_hex[2:4])
    pkt.src_name    = DEVICE_HEX_TO_NAME.get(pkt.src_hex[:2])
    pkt.src_subid   = str(int(pkt.src_hex[2:4],16))
    pkt.src_room    = ROOM_HEX_TO_NAME.get(pkt.src_hex[2:4])

    cmd_n = CMD_HEX_TO_NAME.get(pkt.cmd_hex)
    pkt.cmd_name = cmd_n if cmd_n else pkt.cmd_hex

    pkt.value = pkt.value_hex
    pkt.time  = time.time()
    pkt.flag  = None
    return pkt


# -------------- 기기별 상태 파싱 --------------

def thermo_parse(value_hex: str, config=None) -> dict:
    if config:
        init_temp = int(config.get('User','init_temp',fallback='22'))
    else:
        init_temp = 22

    heat_mode = 'off'
    if value_hex[:2] == '11':
        heat_mode = 'heat'

    away_flag = 'true' if value_hex[2:4] == '01' else 'false'
    if heat_mode == 'heat':
        set_temp = int(value_hex[4:6],16)
    else:
        set_temp = init_temp

    cur_temp = int(value_hex[8:10],16)
    return {
        'heat_mode':heat_mode,
        'away':away_flag,
        'set_temp':set_temp,
        'cur_temp':cur_temp
    }

def light_parse(value_hex: str, config=None) -> dict:
    if config:
        light_cnt = int(config.get('User','light_count',fallback='4'))
    else:
        light_cnt = 4
    ret = {}
    for i in range(1,light_cnt+1):
        seg = value_hex[(i-1)*2:(i-1)*2+2]
        ret[f"light_{i}"] = 'on' if seg != '00' else 'off'
    return ret

def fan_parse(value_hex: str, _config=None) -> dict:
    preset_dic = {'40':'Low','80':'Medium','c0':'High'}
    state = 'off' if value_hex[:2]=='00' else 'on'
    preset = 'Off'
    if state=='on':
        preset = preset_dic.get(value_hex[4:6],'Low')
    return {'state':state,'preset':preset}

def ac_parse(value_hex: str, _config=None) -> dict:
    mode_dic = {'00':'cool','01':'fan_only','02':'dry','03':'auto'}
    fan_dic  = {'01':'LOW','02':'MEDIUM','03':'HIGH'}

    if value_hex[:2] == '10':
        mode_hex = value_hex[2:4]
        fan_hex  = value_hex[4:6]
        temperature = int(value_hex[8:10],16)
        target      = int(value_hex[10:12],16)
        return {
            'state':mode_dic.get(mode_hex,'cool'),
            'fan':fan_dic.get(fan_hex,'LOW'),
            'temperature':temperature,
            'target':target
        }
    else:
        return {'state':'off','fan':'LOW','temperature':25,'target':23}


# -------------- 엘리베이터 TCP/IP --------------

def call_elevator_tcpip():
    # 원본 코드 참조. 여기선 생략
    pass


# -------------- Query & Send Wait Response --------------

def query_device(context, device_hex, publish=False, enforce=False):
    """
    캐시에서 최근 상태 찾거나, 없으면 query 패킷 전송
    """
    now = time.time()
    for pkt in context.cache_data:
        if enforce:
            break
        if now - pkt.time > POLLING_INTERVAL:
            break
        if (pkt.type_name=='ack' and pkt.src_name=='wallpad' and
            pkt.dest_hex==device_hex and pkt.cmd_name!='query'):
            if context.config.get('Log','show_query_hex',fallback='False')=='True':
                logger.log_info(f'[cache reuse] {pkt.dest_name}{pkt.dest_subid} -> {pkt.data_hex}')
            return pkt

    # cache에 없으므로 query 패킷 보냄
    if context.config.get('Log','show_query_hex',fallback='False')=='True':
        dev_name = DEVICE_HEX_TO_NAME.get(device_hex[:2],'?')
        subid    = int(device_hex[2:4],16)
        log_txt  = f"query {dev_name}{subid}"
    else:
        log_txt  = None

    return send_wait_response(
        context=context,
        dest_hex=device_hex,
        cmd_hex=CMD_NAME_TO_HEX['query'],
        log_txt=log_txt,
        publish=publish
    )


def send_wait_response(context, dest_hex, src_hex=None, cmd_hex=None, value_hex=None,
                       log_txt=None, check_ack=True, publish=True):
    """
    RS485 전송 후 wait_queue에서 응답 패킷 기다림
    """
    if src_hex is None:
        src_hex = DEVICE_NAME_TO_HEX['wallpad'] + '00'
    if cmd_hex is None:
        cmd_hex = CMD_NAME_TO_HEX['state']
    if value_hex is None:
        value_hex = '0'*16

    context.wait_target.put(dest_hex)

    # 기본 결과
    res_pkt = KocomPacket()
    res_pkt.value = '0'*16
    res_pkt.flag  = False

    ret_hex = send_packet(context, dest_hex, src_hex, cmd_hex, value_hex,
                          log_txt=log_txt, check_ack=check_ack)
    if ret_hex:
        try:
            resp = context.wait_queue.get(True, 2)
            if publish:
                publish_status(context, resp)
            res_pkt = resp
        except queue.Empty:
            pass

    context.wait_target.get()
    return res_pkt

def send_packet(context, dest_hex, src_hex, cmd_hex, value_hex,
                log_txt=None, check_ack=True):
    """
    기존 send() 함수
    - RS485Wrapper를 통해 패킷 전송
    - ACK 기다림
    """
    context.send_lock.acquire()
    context.ack_data_list.clear()
    result_hex = None

    seq_keys = ['c','d','e','f']  # 4회 재시도
    for seq_key in seq_keys:
        # payload = '30b' + seq_key + '00' + dest + src + cmd + value
        payload_hex = TYPE_NAME_TO_HEX['send'] + seq_key + '00' + dest_hex + src_hex + cmd_hex + value_hex
        full_hex = HEADER_HEX + payload_hex + checksum(payload_hex) + TRAILER_HEX

        try:
            ok = context.rs485.write(bytearray.fromhex(full_hex))
            if not ok:
                raise Exception('write returned False')
        except Exception as e:
            logger.log_error(f'[RS485] Write error: {e}')
            break

        if log_txt:
            logger.log_info(f'[SEND|{log_txt}] {full_hex}')

        if not check_ack:
            time.sleep(1)
            result_hex = full_hex
            break

        # ack pattern
        ack_pattern = TYPE_NAME_TO_HEX['ack'] + seq_key + '00' + src_hex + dest_hex + cmd_hex + value_hex
        context.ack_data_list.append(ack_pattern)

        try:
            context.ack_queue.get(True, 1.3 + 0.2*random.random())
            # ack ok
            if context.config.get('Log','show_recv_hex',fallback='False')=='True':
                logger.log_info('[ACK] OK')
            result_hex = full_hex
            break
        except queue.Empty:
            pass

    if not result_hex:
        logger.log_info('[RS485] send failed. closing & reconnect soon.')
        context.rs485.close()

    context.ack_data_list.clear()
    context.send_lock.release()
    return result_hex


def publish_status(context, packet_obj):
    """
    RS485 수신된 packet_obj를 해석하여 MQTT에 상태 전달
    """
    mqtt_client = context.mqtt_client
    if not mqtt_client:
        return

    if packet_obj.type_name=='send' and packet_obj.dest_name=='wallpad':
        if packet_obj.src_name=='thermo' and packet_obj.cmd_name=='state':
            status = thermo_parse(packet_obj.value_hex, context.config)
            logger.log_info(f'[MQTT publish|thermo] id[{packet_obj.src_subid}] {status}')
            mqtt_client.publish(f"kocom/room/thermo/{packet_obj.src_subid}/state", json.dumps(status))

        elif packet_obj.src_name=='ac' and packet_obj.cmd_name=='state':
            status = ac_parse(packet_obj.value_hex, context.config)
            logger.log_info(f'[MQTT publish|ac] id[{packet_obj.src_subid}] {status}')
            mqtt_client.publish(f"kocom/room/ac/{packet_obj.src_subid}/state", json.dumps(status), retain=True)

        elif packet_obj.src_name=='fan' and packet_obj.cmd_name=='state':
            status = fan_parse(packet_obj.value_hex, context.config)
            logger.log_info(f'[MQTT publish|fan] room[{packet_obj.src_room}] {status}')
            mqtt_client.publish(f"kocom/{packet_obj.src_room}/fan/state", json.dumps(status))

        elif packet_obj.src_name=='light' and packet_obj.cmd_name=='state':
            status = light_parse(packet_obj.value_hex, context.config)
            logger.log_info(f'[MQTT publish|light] room[{packet_obj.src_room}] {status}')
            mqtt_client.publish(f"kocom/{packet_obj.src_room}/light/state", json.dumps(status))

        elif packet_obj.src_name=='gas':
            status = {'state': packet_obj.cmd_name}
            logger.log_info(f'[MQTT publish|gas] {status}')
            mqtt_client.publish("kocom/livingroom/gas/state", json.dumps(status))

        elif packet_obj.src_name=='air':
            logger.log_info('[MQTT publish|air] ...')

    elif packet_obj.type_name=='send' and packet_obj.dest_name=='elevator':
        floor = int(packet_obj.value_hex[2:4],16)
        rs485_floor = int(context.config.get('Elevator','rs485_floor',fallback='0'))
        if rs485_floor!=0:
            status = {'floor': floor}
            if rs485_floor==floor:
                status['state']='off'
        else:
            status = {'state':'off'}
        logger.log_info(f'[MQTT publish|elevator] {status}')
        mqtt_client.publish("kocom/myhome/elevator/state", json.dumps(status))
