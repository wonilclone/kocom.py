import logging

# 전역 logger 생성
logger = logging.getLogger("MyCustomLogger")
logger.setLevel(logging.INFO)  # 기본 레벨: INFO

# 포매터 설정 (시간/레벨/메시지 출력 예시)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

# 스트림 핸들러 (콘솔 출력용)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

# logger에 핸들러 추가
logger.addHandler(stream_handler)

def set_log_level(level_name: str = logging.DEBUG):
    level_map = {
        'ERROR': logging.ERROR,
        'WARNING': logging.WARNING,
        'INFO': logging.INFO,
        'DEBUG': logging.DEBUG
    }
    logger.setLevel(level_map.get(level_name.upper(), logging.INFO))

def log_error(message: str):
    logger.error(message)

def log_warning(message: str):
    logger.warning(message)

def log_info(message: str):
    logger.info(message)

def log_debug(message: str):
    logger.debug(message)
