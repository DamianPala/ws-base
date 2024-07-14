#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
import socketio.exceptions

import functools
import traceback
from typing import Callable, Type, Union
from ws_base.ws_base import SerializableException

from .common import PACKAGE_PATH, SERVER_DEFAULT_HOST, SERVER_DEFAULT_PORT, AUTH_KEY, Req, Rsp, Status, MyDataClass
from ws_base import ServerBase, generate_selfsigned_cert, get_dns_names_from_cert

log = logger.get_logger(__name__)

SERVER_NAME = 'My Server'
CERTFILE_PATH = PACKAGE_PATH / 'server_cert.pem'
KEYFILE_PATH = PACKAGE_PATH / 'server_key.pem'
AUTH_KEYFILE_PATH = PACKAGE_PATH / 'auth_private_key.pem'


class Server(ServerBase):
    def __init__(self, hostname: str = SERVER_DEFAULT_HOST, port: int = SERVER_DEFAULT_PORT) -> None:
        if not CERTFILE_PATH.exists() or not KEYFILE_PATH.exists():
            log.info(f'Generating new SSL certificate for hostname: {hostname}')
            self._generate_new_cert(hostname)
        else:
            dns_names = get_dns_names_from_cert(CERTFILE_PATH.read_bytes())
            if hostname not in dns_names:
                log.info(f'Incompatible SSL certificate. Generating new for hostname: {hostname}')
                self._generate_new_cert(hostname)

        super().__init__(hostname,
                         port,
                         certfile=CERTFILE_PATH.as_posix(),
                         keyfile=KEYFILE_PATH.as_posix())
        self.value = 1
        self.param = 10
        self.result = self.param * 2
        self.dataclass = MyDataClass(1, 'value')

    def start(self) -> None:
        log.info(f'Starting {SERVER_NAME}.')
        super().start()
        log.info(f'{SERVER_NAME} started at url: {self.url}')

    def close(self) -> None:
        log.info(f'Closing {SERVER_NAME}.')
        super().close()
        log.info(f'{SERVER_NAME} closed.')

    def callbacks(self) -> None:
        @self.sio.event
        def connect(sid, _, auth) -> None:
            log.info(f'Connect client: {sid}')
            if auth != AUTH_KEY:
                raise socketio.exceptions.ConnectionRefusedError('Authentication failed')

        @self.sio.event
        def disconnect(sid) -> None:
            log.info(f'Disconnect client: {sid}')

        @self.handle_request(Req)
        def get_value(_1, _2, _3) -> Rsp:
            return Rsp(status=Status.SUCCESS, data=self._get_value())

        @self.handle_request(Req)
        def set_value(_1, _2, data) -> Rsp:
            self.value = data
            return Rsp(status=Status.SUCCESS, data=self._get_value())

        @self.handle_request(Req)
        def method(_1, _2, data) -> Rsp:
            self.param = data
            return Rsp(status=Status.SUCCESS, data=self.result)

        @self.handle_request(Req)
        def get_dataclass(_1, _2, _3) -> Rsp:
            return Rsp(status=Status.SUCCESS, data=self.dataclass.to_dict())

    def _get_value(self) -> int:
        return self.value

    @staticmethod
    def _generate_new_cert(hostname: str) -> None:
        cert_pem, key_pem = generate_selfsigned_cert(hostname=hostname)
        CERTFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CERTFILE_PATH.write_bytes(cert_pem)
        KEYFILE_PATH.write_bytes(key_pem)
