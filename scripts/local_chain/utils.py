import docker

from local_chain import config


def get_docker_network():
    client = docker.from_env()
    try:
        return client.networks.get(config.DOCKER_NETWORK)
    except docker.errors.NotFound:
        return None

def create_network_if_not_existed():
    client = docker.from_env()
    if not get_docker_network():
        client.networks.create(config.DOCKER_NETWORK, attachable=True)

def get_containers(prefix):
    # Match local chain naming.
    client = docker.from_env()
    containers = [c for c in client.containers.list() if c.name.startswith(prefix)]
    containers.sort(key=lambda x: x.name)
    return containers
