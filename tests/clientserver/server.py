#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
from decimal import Decimal
from wsbase import Status, Rsp, BaseServer

from .common import PACKAGE_PATH, SERVER_DEFAULT_URL, AUTH_KEY, MainClassData, SubClassData, MainClassBase, SubClassBase

log = logger.get_logger(__name__)

SERVER_NAME = 'My Server'
CERTFILE_PATH = PACKAGE_PATH / 'server_cert.pem'
KEYFILE_PATH = PACKAGE_PATH / 'server_key.pem'


class Server(BaseServer):
    def __init__(self, url: str = SERVER_DEFAULT_URL) -> None:
        super().__init__(url=url,
                         certfile_path=CERTFILE_PATH,
                         keyfile_path=KEYFILE_PATH,
                         generate_cert=True,
                         auth_data=AUTH_KEY)
        self.value = 1
        self.param = 10
        self.result = self.param * 2
        self.dataclass = MainClassData(
            id=1, name="Example", values=[Decimal('1.1'), Decimal('2.2')], nested=SubClassData(value=Decimal('10.5'))
        )
        self.basemodel = MainClassBase(
           id=1, name="Example", values=[Decimal('1.1'), Decimal('2.2')], nested=SubClassBase(value=Decimal('10.5'))
        )

    def start(self) -> None:
        log.info(f'Starting {SERVER_NAME}.')
        super().start()
        log.info(f'{SERVER_NAME} started at URL: {self.url}')

    def close(self) -> None:
        log.info(f'Closing {SERVER_NAME}.')
        super().close()
        log.info(f'{SERVER_NAME} closed.')

    def callbacks(self) -> None:
        @self.handle_request()
        async def get_value(_1, _2, _3) -> Rsp:
            return Rsp(status=Status.SUCCESS, data=self._get_value())

        @self.handle_request()
        async def set_value(_1, _2, data) -> Rsp:
            self.value = data
            return Rsp(status=Status.SUCCESS, data=self._get_value())

        @self.handle_request()
        async def method(_1, _2, data) -> Rsp:
            self.param = data
            return Rsp(status=Status.SUCCESS, data=self.result)

        @self.handle_request()
        async def get_dataclass(_1, _2, _3) -> Rsp:
            return Rsp(status=Status.SUCCESS, data=self.dataclass)

        @self.handle_request()
        async def set_dataclass(_1, _2, data) -> Rsp:
            self.dataclass = MainClassData.from_json(data)
            return Rsp(status=Status.SUCCESS, data=self.dataclass)

        @self.handle_request()
        async def get_basemodel(_1, _2, _3) -> Rsp:
            return Rsp(status=Status.SUCCESS, data=self.basemodel)

        @self.handle_request()
        async def set_basemodel(_1, _2, data) -> Rsp:
            self.basemodel = MainClassBase.from_json(data)
            return Rsp(status=Status.SUCCESS, data=self.basemodel)

        @self.handle_request()
        async def increment(_1, _2, data) -> Rsp:
            return Rsp(status=Status.SUCCESS, data=data + 1)

    def _get_value(self) -> int:
        return self.value
