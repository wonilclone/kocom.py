"""
mqtt_handler.py
- MQTT 초기화 & 콜백
- 명령 토픽 해석 -> RS485 제어
- Home Assistant Discovery
"""

import json
import threading
import time

from paho.mqtt import client as mqtt

import logger
from device_parser import (
    CMD_NAME_TO_HEX,
    DEVICE_NAME_TO_HEX,
    ROOM_NAME_TO_HEX,
    SW_VERSION,
    call_elevator_tcpip,
    query_device,
    send_packet,
    send_wait_response,
)


def init_mqtt_client(context):
    """
    MQTT 클라이언트 생성 및 연결
    """
    config = context.config
    client = mqtt.Client()

    client.on_connect    = lambda c,u,f,rc: mqtt_on_connect(context, c,u,f,rc)
    client.on_disconnect = lambda c,u,rc: mqtt_on_disconnect(context, c,u,rc)
    client.on_subscribe  = lambda c,u,mid,qos: mqtt_on_subscribe(context, c,u,mid,qos)
    client.on_message    = lambda c,u,m: mqtt_on_message(context, c,u,m)

    if config.getboolean('MQTT','mqtt_allow_anonymous'):
        user = config.get('MQTT','mqtt_username',fallback='')
        pwd  = config.get('MQTT','mqtt_password',fallback='')
        logger.log_info("[MQTT] connecting with username/password")
        client.username_pw_set(username=user, password=pwd)
    else:
        logger.log_info("[MQTT] connecting (anonymous)")

    broker_host = config.get('MQTT','mqtt_server',fallback='localhost')
    broker_port = int(config.get('MQTT','mqtt_port',fallback=1883))

    for retry_cnt in range(1,6):
        try:
            client.connect(broker_host, broker_port, 60)
            client.loop_start()
            context.mqtt_client = client
            return client
        except:
            logger.log_error(f"[MQTT] connection fail #{retry_cnt}")
            time.sleep(5)

    return None

# ------------------ 콜백 ------------------

def mqtt_on_connect(_context, client, _userdata, _flags, rc):
    if rc == 0:
        logger.log_info("[MQTT] Connected OK")
        client.subscribe('kocom/#',0)
    else:
        logger.log_error(f"[MQTT] Connect error rc={rc}")

def mqtt_on_disconnect(_context, _client, _userdata, rc):
    logger.log_error(f"[MQTT] Disconnected rc={rc}")

def mqtt_on_subscribe(_context, _client, _userdata, mid, granted_qos):
    logger.log_info(f"[MQTT] Subscribed: mid={mid}, qos={granted_qos}")

def mqtt_on_message(context, _client, _userdata, msg):
    """
    kocom/xxx/.../command
    """
    command_str = msg.payload.decode('utf-8','ignore').strip()
    topic_parts = msg.topic.split('/')
    if topic_parts[-1] != 'command':
        return

    logger.log_info(f"[MQTT RECV] topic={msg.topic}, command={command_str}")

    # 예: kocom/room/thermo/3/heat_mode/command
    try:
        if 'thermo' in topic_parts and 'heat_mode' in topic_parts:
            handle_thermo_heat_mode(context, topic_parts, command_str)
        elif 'thermo' in topic_parts and 'set_temp' in topic_parts:
            handle_thermo_set_temp(context, topic_parts, command_str)
        elif 'ac' in topic_parts and 'ac_mode' in topic_parts:
            handle_ac_mode(context, topic_parts, command_str)
        elif 'ac' in topic_parts and 'fan_mode' in topic_parts:
            handle_ac_fan_mode(context, topic_parts, command_str)
        elif 'ac' in topic_parts and 'set_temp' in topic_parts:
            handle_ac_set_temp(context, topic_parts, command_str)
        elif 'light' in topic_parts:
            handle_light_command(context, topic_parts, command_str)
        elif 'gas' in topic_parts:
            handle_gas_command(context, topic_parts, command_str)
        elif 'elevator' in topic_parts:
            handle_elevator_command(context, topic_parts, command_str)
        elif 'fan' in topic_parts and 'set_preset_mode' in topic_parts:
            handle_fan_preset(context, topic_parts, command_str)
        elif 'fan' in topic_parts:
            handle_fan_command(context, topic_parts, command_str)
        elif 'query' in topic_parts:
            # query → poll_state(enforce=True)
            if command_str.upper() == 'PRESS' and context.poll_state_cb:
                context.poll_state_cb(context, enforce=True)
    except Exception as e:
        logger.log_error(f"[MQTT] handle command error: {e}")


# ------------------ Thermo Heat Mode ------------------

def handle_thermo_heat_mode(context, topic_parts, cmd_str):
    dev_hex = DEVICE_NAME_TO_HEX['thermo'] + f"{int(topic_parts[3]):02x}"
    heat_dic = {'heat':'11','off':'00'}

    query_device(context, dev_hex)
    init_temp_hex = f"{int(context.config.get('User','thermo_init_temp',fallback='20')):02x}"

    value_hex = heat_dic.get(cmd_str,'00') + '00' + init_temp_hex + '0000000000'
    send_wait_response(context, dev_hex, value_hex=value_hex, log_txt='thermo heatmode')


def handle_thermo_set_temp(context, topic_parts, cmd_str):
    dev_hex = DEVICE_NAME_TO_HEX['thermo'] + f"{int(topic_parts[3]):02x}"
    try:
        new_temp = int(float(cmd_str))
    except:
        new_temp = 20
    settemp_hex = f"{new_temp:02x}"
    value_hex = "1100" + settemp_hex + "0000000000"
    send_wait_response(context, dev_hex, value_hex=value_hex, log_txt='thermo settemp')


# ------------------ AC ------------------

def handle_ac_mode(context, topic_parts, cmd_str):
    dev_hex = DEVICE_NAME_TO_HEX['ac'] + f"{int(topic_parts[3]):02x}"
    acmode_dic = {'off':'00','cool':'00','fan_only':'01','dry':'02','auto':'03'}

    if cmd_str=='off':
        value_hex = "00" + acmode_dic['off'] + "000000000000"
    else:
        dmode = context.config.get('User','ac_init_mode',fallback='00')
        mode_hex = acmode_dic.get(cmd_str, dmode)
        value_hex = "10" + mode_hex + "000000000000"

    send_wait_response(context, dev_hex, value_hex=value_hex, log_txt='ac mode')

def handle_ac_fan_mode(context, topic_parts, cmd_str):
    dev_hex = DEVICE_NAME_TO_HEX['ac'] + f"{int(topic_parts[3]):02x}"
    fan_dic = {'LOW':'01','MEDIUM':'02','HIGH':'03'}
    init_fan = context.config.get('User','ac_init_fan_mode',fallback='01')
    fan_hex = fan_dic.get(cmd_str, init_fan)
    value_hex = "1010" + fan_hex + "0000000000"
    send_wait_response(context, dev_hex, value_hex=value_hex, log_txt='ac fanmode')

def handle_ac_set_temp(context, topic_parts, cmd_str):
    dev_hex = DEVICE_NAME_TO_HEX['ac'] + f"{int(topic_parts[3]):02x}"
    try:
        new_t = int(float(cmd_str))
    except:
        new_t = 23
    st_hex = f"{new_t:02x}"
    value_hex = "1010000000" + st_hex + "0000"
    send_wait_response(context, dev_hex, value_hex=value_hex, log_txt='ac settemp')


# ------------------ Light ------------------

def handle_light_command(context, topic_parts, cmd_str):
    room_hex = ROOM_NAME_TO_HEX.get(topic_parts[1], '00')
    dev_hex  = DEVICE_NAME_TO_HEX['light'] + room_hex
    q_pkt = query_device(context, dev_hex)
    if q_pkt.flag is False:
        return

    onoff_hex = 'ff' if cmd_str=='on' else '00'
    light_id = int(topic_parts[3])
    val_hex = q_pkt.value

    if light_id>0:
        while light_id>0:
            n = light_id%10
            start_idx = (n*2)-2
            val_hex = val_hex[:start_idx] + onoff_hex + val_hex[start_idx+2:]
            light_id//=10
        send_wait_response(context, dev_hex, value_hex=val_hex, log_txt='light')
    else:
        send_wait_response(context, dev_hex, value_hex=val_hex, log_txt='light')


# ------------------ Gas ------------------

def handle_gas_command(context, topic_parts, cmd_str):
    room_hex = ROOM_NAME_TO_HEX.get(topic_parts[1], '00')
    dev_hex  = DEVICE_NAME_TO_HEX['gas'] + room_hex
    if cmd_str!='off':
        logger.log_info('[gas] only off is supported')
        return
    off_hex = CMD_NAME_TO_HEX['off']
    send_wait_response(context, dev_hex, cmd_hex=off_hex, log_txt='gas')


# ------------------ Elevator ------------------

def handle_elevator_command(context, topic_parts, cmd_str):
    """
    handle_elevator_command 함수에 client가 선언되지 않았던 문제를,
    context.mqtt_client를 사용하도록 수정
    """
    dev_hex = DEVICE_NAME_TO_HEX['elevator'] + ROOM_NAME_TO_HEX.get(topic_parts[1],'00')
    client = context.mqtt_client

    state_on  = json.dumps({'state':'on'})
    state_off = json.dumps({'state':'off'})

    if cmd_str=='on':
        elev_type = context.config.get('Elevator','type',fallback='rs485')
        if elev_type=='rs485':
            wallpad_hex = DEVICE_NAME_TO_HEX['wallpad']+'00'
            cmd_on_hex = CMD_NAME_TO_HEX['on']
            ret_elev = send_packet(context, wallpad_hex, dev_hex, cmd_on_hex, '0'*16,
                                   log_txt='elevator', check_ack=False)
        else:
            ret_elev = call_elevator_tcpip()

        if not ret_elev:
            logger.log_debug('[Elevator] send fail or no response')
            return

        # MQTT
        threading.Thread(target=lambda:
            client.publish("kocom/myhome/elevator/state", state_on)
        ).start()

        # rs485_floor=='' → 5초 후 off
        if context.config.get('Elevator','rs485_floor',fallback='')=='':
            threading.Timer(5, lambda:
                client.publish("kocom/myhome/elevator/state", state_off)
            ).start()

    elif cmd_str=='off':
        threading.Thread(target=lambda:
            client.publish("kocom/myhome/elevator/state", state_off)
        ).start()


# ------------------ Fan ------------------

def handle_fan_preset(context, topic_parts, cmd_str):
    dev_hex = DEVICE_NAME_TO_HEX['fan'] + ROOM_NAME_TO_HEX.get(topic_parts[1],'00')
    onoff_dic = {'off':'0000','on':'1101'}
    speed_dic = {'Off':'00','Low':'40','Medium':'80','High':'c0'}

    if cmd_str=='Off':
        onoff_hex = onoff_dic['off']
        sp_hex    = speed_dic['Off']
    else:
        onoff_hex = onoff_dic['on']
        sp_hex    = speed_dic.get(cmd_str,'40')

    value_hex = onoff_hex + sp_hex + '0'*10
    send_wait_response(context, dev_hex, value_hex=value_hex, log_txt='fan preset')


def handle_fan_command(context, topic_parts, cmd_str):
    dev_hex = DEVICE_NAME_TO_HEX['fan'] + ROOM_NAME_TO_HEX.get(topic_parts[1],'00')
    onoff_dic = {'off':'0000','on':'1101'}
    spd_dic   = {'Low':'40','Medium':'80','High':'c0'}
    init_fan  = context.config.get('User','init_fan_mode',fallback='Low')

    onoff_hex = onoff_dic.get(cmd_str,'0000')
    sp_hex    = spd_dic.get(init_fan,'40')
    val_hex = onoff_hex + sp_hex + '0'*10
    send_wait_response(context, dev_hex, value_hex=val_hex, log_txt='fan')


# ------------------ Discovery ------------------

def discovery(context):
    """
    Home Assistant Discovery (원본 코드 대부분 유사)
    """
    config = context.config
    dev_list = [x.strip() for x in config.get('Device','enabled',fallback='').split(',')]
    for dev_str in dev_list:
        parts = dev_str.split('_')
        dev = parts[0]
        sub = parts[1] if len(parts)>1 else ''
        publish_discovery(context, dev, sub)

    # query
    publish_discovery(context, 'query')

def publish_discovery(context, dev, sub=''):
    """
    원본 publish_discovery 로직을 context 기반으로 정리.
    지정된 dev(기기 종류)에 맞는 Home Assistant Discovery 정보를 구성하여 MQTT에 퍼블리시한다.
    """
    mqtt_client = context.mqtt_client
    config = context.config
    log_message = ""

    def publish_topic(topic: str, payload: dict, **kwargs):
        """
        discovery용 토픽에 최종적으로 publish하는 내부 헬퍼 함수
        """
        if topic and payload:
            payload['device'] = {
                'name': '코콤 스마트 월패드',
                'ids': 'kocom_smart_wallpad',
                'mf': 'KOCOM',
                'mdl': '스마트 월패드',
                'sw': SW_VERSION
            }
            mqtt_client.publish(topic, json.dumps(payload), **kwargs)

    # ----------------------------------------------------------------
    # 각 dev 유형별로 Discovery 정보 설정
    # ----------------------------------------------------------------
    if dev == 'fan':
        topic = 'homeassistant/fan/kocom_wallpad_fan/config'
        payload = {
            'name': 'Kocom Wallpad Fan',
            'cmd_t': f'kocom/{sub}/fan/command',
            'stat_t': f'kocom/{sub}/fan/state',
            'stat_val_tpl': '{{ value_json.state }}',
            'pr_mode_stat_t': f'kocom/{sub}/fan/state',
            'pr_mode_val_tpl': '{{ value_json.preset }}',
            'pr_mode_cmd_t': f'kocom/{sub}/fan/set_preset_mode/command',
            'pr_mode_cmd_tpl': '{{ value }}',
            'pr_modes': ['Off', 'Low', 'Medium', 'High'],
            'pl_on': 'on',
            'pl_off': 'off',
            'qos': 0,
            'uniq_id': f'kocom_wallpad_{dev}'
        }
        log_message = f'[MQTT Discovery|{dev}] data[{topic}]'
        publish_topic(topic, payload)

    elif dev == 'air':
        air_attr = {
            'pm10':        ['molecule', 'µg/m³'],
            'pm25':        ['molecule', 'µg/m³'],
            'co2':         ['molecule-co2', 'ppm'],
            'tvocs':       ['molecule', 'ppb'],
            'temperature': ['thermometer', '°C'],
            'humidity':    ['water-percent', '%'],
            'score':       ['periodic-table', '%']
        }
        for key, (icon, unit) in air_attr.items():
            topic = f'homeassistant/sensor/kocom_wallpad_air_{key}/config'
            payload = {
                'name': f'kocom_air_{key}',
                'stat_t': 'kocom/livingroom/air/state',
                'val_tpl': f'{{{{ value_json.{key} }}}}',
                'qos': 0,
                'uniq_id': f'kocom_air_{key}',
                'icon': f'mdi:{icon}',
                'unit_of_meas': unit
            }
            log_message = f'[MQTT Discovery|{dev}] data[{topic}]'
            publish_topic(topic, payload, retain=True)

    elif dev == 'gas':
        topic = 'homeassistant/switch/kocom_wallpad_gas/config'
        payload = {
            'name': 'Kocom Wallpad Gas',
            'cmd_t': 'kocom/livingroom/gas/command',
            'stat_t': 'kocom/livingroom/gas/state',
            'val_tpl': '{{ value_json.state }}',
            'pl_on': 'on',
            'pl_off': 'off',
            'ic': 'mdi:gas-cylinder',
            'qos': 0,
            'uniq_id': f'kocom_wallpad_{dev}'
        }
        log_message = f'[MQTT Discovery|{dev}] data[{topic}]'
        publish_topic(topic, payload)

    elif dev == 'elevator':
        topic = 'homeassistant/switch/kocom_wallpad_elevator/config'
        payload = {
            'name': 'Kocom Wallpad Elevator',
            'cmd_t': 'kocom/myhome/elevator/command',
            'stat_t': 'kocom/myhome/elevator/state',
            'val_tpl': '{{ value_json.state }}',
            'pl_on': 'on',
            'pl_off': 'off',
            'ic': 'mdi:elevator',
            'qos': 0,
            'uniq_id': f'kocom_wallpad_{dev}'
        }
        log_message = f'[MQTT Discovery|{dev}] data[{topic}]'
        publish_topic(topic, payload)

    elif dev == 'light':
        light_count = int(config.get('User', 'light_count', fallback='1'))
        for num in range(1, light_count + 1):
            topic = f'homeassistant/light/kocom_{sub}_light{num}/config'
            payload = {
                'name': f'Kocom {sub} Light{num}',
                'cmd_t': f'kocom/{sub}/light/{num}/command',
                'stat_t': f'kocom/{sub}/light/state',
                'stat_val_tpl': f'{{{{ value_json.light_{num} }}}}',
                'pl_on': 'on',
                'pl_off': 'off',
                'qos': 0,
                'uniq_id': f'kocom_{sub}_{dev}{num}'
            }
            log_message = f'[MQTT Discovery|{dev}{num}] data[{topic}]'
            publish_topic(topic, payload)

    elif dev == 'thermo':
        from device_parser import ROOM_NAME_TO_HEX
        num = int(ROOM_NAME_TO_HEX.get(sub, '00'), 16)  # 예: '01' -> 1
        topic = f'homeassistant/climate/kocom_{sub}_thermostat/config'
        payload = {
            'name': f'Kocom {sub} Thermostat',
            'mode_cmd_t': f'kocom/room/thermo/{num}/heat_mode/command',
            'mode_stat_t': f'kocom/room/thermo/{num}/state',
            'mode_stat_tpl': '{{ value_json.heat_mode }}',
            'temp_cmd_t': f'kocom/room/thermo/{num}/set_temp/command',
            'temp_stat_t': f'kocom/room/thermo/{num}/state',
            'temp_stat_tpl': '{{ value_json.set_temp }}',
            'curr_temp_t': f'kocom/room/thermo/{num}/state',
            'curr_temp_tpl': '{{ value_json.cur_temp }}',
            'modes': ['off', 'heat'],
            'min_temp': 20,
            'max_temp': 30,
            'ret': 'false',
            'qos': 0,
            'uniq_id': f'kocom_wallpad_{dev}{num}'
        }
        log_message = f'[MQTT Discovery|{dev}{num}] data[{topic}]'
        publish_topic(topic, payload)

    elif dev == 'ac':
        from device_parser import ROOM_NAME_TO_HEX
        num = int(ROOM_NAME_TO_HEX.get(sub, '00'), 16)
        topic = f'homeassistant/climate/kocom_{num}_ac/config'
        payload = {
            'name': f'kocom_ac_{num}',
            'mode_cmd_t': f'kocom/room/ac/{num}/ac_mode/command',
            'mode_stat_t': f'kocom/room/ac/{num}/state',
            'mode_stat_tpl': '{{ value_json.state }}',
            'fan_mode_cmd_t': f'kocom/room/ac/{num}/fan_mode/command',
            'fan_mode_stat_t': f'kocom/room/ac/{num}/state',
            'fan_mode_stat_tpl': '{{ value_json.fan }}',
            'temp_cmd_t': f'kocom/room/ac/{num}/set_temp/command',
            'temp_stat_t': f'kocom/room/ac/{num}/state',
            'temp_stat_tpl': '{{ value_json.target }}',
            'curr_temp_t': f'kocom/room/ac/{num}/state',
            'curr_temp_tpl': '{{ value_json.temperature }}',
            'modes': ['off', 'cool', 'fan_only', 'dry', 'auto'],
            'fan_modes': ['LOW', 'MEDIUM', 'HIGH'],
            'min_temp': 10,
            'max_temp': 30,
            'uniq_id': f'kocom_ac_{num}'
        }
        log_message = f'[MQTT Discovery|{dev}{sub}] data[{topic}]'
        publish_topic(topic, payload, retain=True)

    elif dev == 'query':
        topic = 'homeassistant/button/kocom_wallpad_query/config'
        payload = {
            'name': 'Kocom Wallpad Query',
            'cmd_t': 'kocom/myhome/query/command',
            'qos': 0,
            'uniq_id': f'kocom_wallpad_{dev}'
        }
        log_message = f'[MQTT Discovery|{dev}] data[{topic}]'
        publish_topic(topic, payload)

    if log_message and config.getboolean('Log', 'show_mqtt_publish', fallback=False):
        logger.log_info(log_message)
