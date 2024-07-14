#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
from typing import Any
from decimal import Decimal
from datetime import datetime

from . import common
from .common import (SERVER_DEFAULT_URL, AUTH_KEY, Req, Rsp, Event, MyDataClass)
from ws_base import ClientBase, connect, build_exception_map

log = logger.get_logger(__name__)


class Client(ClientBase):
    def __init__(self, server_url: str = SERVER_DEFAULT_URL, is_autoconnect: bool = False):
        super().__init__(server_url,
                         build_exception_map(common),
                         auth_data=AUTH_KEY,
                         ssl_verify=False,
                         is_autoconnect=is_autoconnect)

    @connect
    def get_value(self) -> Any:
        self.make_request(Req(Event.GET_VALUE))
        rsp = self._get_and_verify_response()
        return rsp.data

    @connect
    def set_value(self, value: Any) -> Any:
        self.make_request(Req(Event.SET_VALUE, data=value))
        rsp = self._get_and_verify_response()
        return rsp.data

    @connect
    def method(self, param: Any) -> Any:
        self.make_request(Req(Event.METHOD, data=param))
        rsp = self._get_and_verify_response()
        return rsp.data

    @connect
    def get_dataclass(self) -> MyDataClass:
        self.make_request(Req(Event.GET_DATACLASS))
        rsp = self._get_and_verify_response()
        return MyDataClass.from_dict(rsp.data)

    def callbacks(self) -> None:
        @self.handle_response(Rsp)
        def get_value() -> None:
            log.debug(f'Received {self.rsp.event} from {self.server_url}')

        @self.handle_response(Rsp)
        def set_value() -> None:
            log.debug(f'Received {self.rsp.event} from {self.server_url}')

        @self.handle_response(Rsp)
        def method() -> None:
            log.debug(f'Received {self.rsp.event} from {self.server_url}')

        @self.handle_response(Rsp)
        def get_dataclass() -> None:
            log.debug(f'Received {self.rsp.event} from {self.server_url}')
