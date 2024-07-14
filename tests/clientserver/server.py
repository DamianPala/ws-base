#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
from decimal import Decimal

from .common import PACKAGE_PATH, SERVER_DEFAULT_URL, AUTH_KEY, Req, Rsp, Status, MyDataClass
from ws_base import ServerBase

log = logger.get_logger(__name__)

SERVER_NAME = 'My Server'
CERTFILE_PATH = PACKAGE_PATH / 'server_cert.pem'
KEYFILE_PATH = PACKAGE_PATH / 'server_key.pem'


class Server(ServerBase):
    def __init__(self, url: str = SERVER_DEFAULT_URL) -> None:
        super().__init__(url=url,
                         certfile_path=CERTFILE_PATH,
                         keyfile_path=KEYFILE_PATH,
                         generate_cert=True,
                         auth_key=AUTH_KEY)
        self.value = 1
        self.param = 10
        self.result = self.param * 2
        self.dataclass = MyDataClass(Decimal(1), 'value')

    def start(self) -> None:
        log.info(f'Starting {SERVER_NAME}.')
        super().start()
        log.info(f'{SERVER_NAME} started at url: {self.url}')

    def close(self) -> None:
        log.info(f'Closing {SERVER_NAME}.')
        super().close()
        log.info(f'{SERVER_NAME} closed.')

    def callbacks(self) -> None:
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
