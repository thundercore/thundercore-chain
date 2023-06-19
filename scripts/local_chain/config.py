""" Basic configs for local_chain setup """
import os

from pathlib import Path

# Root dir = .../tt/thunder/local_chain
LOCAL_CHAIN_ROOT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
LOCAL_CHAIN_TEMPLATE_DIR = LOCAL_CHAIN_ROOT_DIR.joinpath("template")
YML_PATH = LOCAL_CHAIN_ROOT_DIR.joinpath("docker-compose.yml")
START_ARGS_PATH = LOCAL_CHAIN_ROOT_DIR.joinpath('tmp', 'start-args.json')
CONFIG_DIR = os.path.realpath(os.path.join(LOCAL_CHAIN_ROOT_DIR, '../..', 'config'))
THUNDER_ROOT = LOCAL_CHAIN_ROOT_DIR.parent
DOCKER_GENERATED_DIR = Path("/.generated")
DOCKER_KEYS_DIR = DOCKER_GENERATED_DIR.joinpath("keys")
DOCKER_FAST_PATH_KEYSTORE = DOCKER_KEYS_DIR.joinpath("fastpath/keystore")
DOCKER_NODE_SETTING_FILE = DOCKER_GENERATED_DIR.joinpath("node_setting.json")
GENERATED_DIR = LOCAL_CHAIN_ROOT_DIR.joinpath(".generated")
KEYS_DIR = GENERATED_DIR.joinpath("keys")
FAST_PATH_KEYSTORE = KEYS_DIR.joinpath("fastpath/keystore")
NODE_SETTING_FILE = GENERATED_DIR.joinpath("node_setting.json")
AUXNET_NAME = "auxnet"
SLOW_PATH_KEYSTORE = KEYS_DIR.joinpath(AUXNET_NAME)
LOG_FILE_IN_CONTAINER = "/logs/thunder.log"
DOCKER_COMPOSE_CMD = ['docker-compose', '-f', str(YML_PATH)]
DOCKER_NETWORK = 'local_chain_default'
