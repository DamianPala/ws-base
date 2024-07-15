#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logger
import pytest
from contextlib import contextmanager
from typing import Tuple

from tests.clientserver import Client, Server, MyError, MainClassData, MainClassBase
from ws_base import ResponseError

log = logger.get_logger(__name__)


class ClientServer:
    def __init__(self, start_server: bool = True):
        self.server = Server()
        self.client = Client(is_autoconnect=False)
        self.start_server = start_server

    def __enter__(self) -> Tuple[Client, Server]:
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.close()

    def start(self) -> Tuple[Client, Server]:
        if self.start_server:
            self.server.start()
            self.client.connect()
        return self.client, self.server

    def close(self):
        self.client.disconnect()
        self.server.close()
        self.server.join()


@contextmanager
def client_server_context():
    cs = ClientServer()
    try:
        yield cs.__enter__()
    finally:
        cs.__exit__(None, None, None)


@pytest.fixture
def clientserver():
    with client_server_context() as (client, server):
        yield client, server


class TestComm:
    def test_get_value(self, clientserver):
        client, server = clientserver
        value = client.get_value()
        log.info('Value:', value)
        assert value == server.value

    def test_set_value(self, clientserver):
        client, server = clientserver
        new_value = server.value + 1
        value = client.set_value(new_value)
        log.info('Value:', value)
        assert value == server.value == new_value

    def test_run_method(self, clientserver):
        client, server = clientserver
        new_param = server.param + 1
        result = client.method(new_param)
        log.info('Result:', result)
        assert server.param == new_param
        assert result == server.result

    def test_data_types(self):
        ...

    def test_get_dataclass(self, clientserver):
        client, server = clientserver
        value = client.get_dataclass()
        log.info('Value:', value)
        assert value == server.dataclass

    def test_set_dataclass(self, clientserver):
        client, server = clientserver
        new_dataclass = MainClassData.from_json(server.dataclass.to_json())
        new_dataclass.id += 1
        assert new_dataclass != server.dataclass
        value = client.set_dataclass(new_dataclass)
        log.info('Value:', value)
        assert value == server.dataclass == new_dataclass

    def test_get_basemodel(self, clientserver):
        client, server = clientserver
        value = client.get_basemodel()
        log.info('Value:', value)
        assert value == server.basemodel

    def test_set_basemodel(self, clientserver):
        client, server = clientserver
        new_basemodel = MainClassBase.from_json(server.basemodel.to_json())
        new_basemodel.id += 1
        assert new_basemodel != server.basemodel
        value = client.set_basemodel(new_basemodel)
        log.info('Value:', value)
        assert value == server.basemodel == new_basemodel


class TestHandleErrors:
    def test_success(self, clientserver):
        client, server = clientserver
        value = client.get_value()
        assert value == server.value

    def test_generic_error(self, clientserver, mocker):
        client, server = clientserver
        exc_msg = 'Invalid data'
        mocker.patch.object(server, '_get_value', side_effect=ValueError(exc_msg))
        with pytest.raises(ResponseError, match=exc_msg) as exc_info:
            client.get_value()
        log.info(str(exc_info.value))
        log.info(str(exc_info.value.tb))

    def test_specific_error(self, clientserver, mocker):
        client, server = clientserver
        exc_msg = 'An error'
        mocker.patch.object(server, '_get_value', side_effect=MyError(exc_msg))
        with pytest.raises(MyError, match=exc_msg) as exc_info:
            client.get_value()
        log.info(str(exc_info.value.tb))
        log.info(str(exc_info.value.event))





def test_dummy():
    ...
    # client, server = clientserver



