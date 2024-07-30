#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
import logger
import pytest
import threading
from contextlib import contextmanager
from typing import Tuple
from decimal import Decimal
from pyinstrument import Profiler

from wsbase import ResponseError
from tests.clientserver import Client, Server, MyError, MainClassData, MainClassBase

log = logger.get_logger(__name__)


class ClientServer:
    def __init__(self, start_server: bool = True) -> None:
        self.server = Server()
        self.client = Client(is_autoconnect=False)
        self.start_server = start_server

    def __enter__(self) -> Tuple[Client, Server]:
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        return self.close()

    def start(self) -> Tuple[Client, Server]:
        if self.start_server:
            self.server.start()
            self.client.connect()
        return self.client, self.server

    def close(self) -> None:
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
def clientserver() -> Tuple[Client, Server]:
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

    def test_data_types(self, clientserver):
        client, server = clientserver

        new_value = None
        value = client.set_value(new_value)
        log.info(f'Type: {type(value)}, value: {value}')
        assert value == server.value == new_value

        new_value = True
        value = client.set_value(new_value)
        log.info(f'Type: {type(value)}, value: {value}')
        assert value == server.value == new_value

        new_value = 123
        value = client.set_value(new_value)
        log.info(f'Type: {type(value)}, value: {value}')
        assert value == server.value == new_value

        new_value = 123.456
        value = client.set_value(new_value)
        log.info(f'Type: {type(value)}, value: {value}')
        assert value == server.value == new_value

        new_value = Decimal(123)
        value = client.set_value(str(new_value))
        log.info(f'Type: {type(value)}, value: {value}')
        assert Decimal(value) == Decimal(server.value) == new_value

        new_value = 'test'
        value = client.set_value(new_value)
        log.info(f'Type: {type(value)}, value: {value}')
        assert value == server.value == new_value

        new_value = b'bytes test'
        value = client.set_value(new_value)
        log.info(f'Type: {type(value)}, value: {value}')
        assert value == server.value == new_value

        new_value = [1, 2, 3]
        value = client.set_value(new_value)
        log.info(f'Type: {type(value)}, value: {value}')
        assert value == server.value == new_value

        new_value = {'key': 123}
        value = client.set_value(new_value)
        log.info(f'Type: {type(value)}, value: {value}')
        assert value == server.value == new_value

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


class TestConnHandling:
    def test_client_retries_when_conn_error(self, clientserver, mocker):
        class SioMock:
            def __init__(self, original_emit):
                self.original_emit = original_emit
                self.cnt = 0

            def emit(self, event, data=None, namespace=None, callback=None):
                self.cnt += 1
                if self.cnt == 1:
                    raise ConnectionError('Simulated error')
                self.original_emit(event, data=data, namespace=namespace, callback=callback)

        client, server = clientserver
        siomock = SioMock(client.sio.emit)
        mocker.patch.object(client.sio, 'emit', new=siomock.emit)
        value = client.get_value()
        log.info('Value:', value)
        assert value == server.value

    def test_client_retries_till_max(self, clientserver, mocker):
        sim_exc = ConnectionError('Simulated error')

        def emit(_, _1=None, _2=None, _3=None):
            raise sim_exc

        client, server = clientserver
        mocker.patch.object(client.sio, 'emit', new=emit)
        with pytest.raises(type(sim_exc), match=str(sim_exc)):
            client.get_value()

    def test_client_reconnects_when_server_restarted(self):
        import multiprocessing
        num_clients = 10
        server_started = multiprocessing.Event()
        manager = multiprocessing.Manager()
        shared_state = manager.dict()

        def start_server():
            server = Server()
            server.start()
            server_started.set()
            while True:
                shared_state['connections'] = server.connections
                time.sleep(0.1)

        def get_server_connections():
            time.sleep(0.11)
            return shared_state['connections']

        def client_test(client):  # noqa
            cnt = 0
            for _ in range(10):
                cnt = client.increment(cnt)
            assert cnt == 10

        server_process = multiprocessing.Process(target=start_server)
        server_started.clear()
        server_process.start()
        server_started.wait()

        clients = [Client(is_autoconnect=True) for _ in range(num_clients)]
        for client in clients:
            client_test(client)

        assert len(get_server_connections()) == num_clients

        server_process.terminate()

        for x in range(3):
            time.sleep(10)

            server_process = multiprocessing.Process(target=start_server)
            server_started.clear()
            server_process.start()
            server_started.wait()

            for client in clients:
                client_test(client)

            assert len(get_server_connections()) == num_clients

            server_process.terminate()

    def test_multithreading(self, clientserver):
        client, server = clientserver

        def thread_worker(req_idx: int) -> None:
            init_req_idx = req_idx
            for _ in range(100):
                rsp = client.increment(req_idx)
                assert rsp == req_idx + 1
                log.info(rsp)
                req_idx += 1
            log.info(f'Worker {client.sid} finished')
            assert req_idx == init_req_idx + 100

        threads = []
        for x in range(3):
            t = threading.Thread(target=thread_worker, args=(10 * x,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()


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
        log.info(str(exc_info.value.tb))  # noqa
        log.info(str(exc_info.value.event))  # noqa


def test_performance():
    num_clients = 10
    message_interval = 0.001
    test_duration = 3
    req_cnt = 0
    start_event = threading.Event()
    profiler = Profiler()

    def client_worker():
        nonlocal req_cnt
        client = Client(is_autoconnect=True)
        wait_event = threading.Event()
        cnt = 0
        start_event.wait()
        while not stop_event.is_set():
            cnt = client.increment(cnt)
            req_cnt += 1
            wait_event.wait(timeout=message_interval)
        client.disconnect()

    stop_event = threading.Event()
    server = Server()
    server.start()

    threads = [threading.Thread(target=client_worker) for _ in range(num_clients)]

    for t in threads:
        t.start()
    time.sleep(1)

    profiler.start()
    start_event.set()
    time.sleep(test_duration)
    stop_event.set()

    for t in threads:
        t.join()
    profile_session = profiler.stop()
    cpu_usage = profile_session.cpu_time / profile_session.duration * 100

    server.close()
    server.join()
    log.info(f'CPU usage: {cpu_usage:.1f}, throughput: {req_cnt / test_duration:.0f} req/s')
