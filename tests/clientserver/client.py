#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
from typing import Optional, Union, List, Dict, Any
from decimal import Decimal
from datetime import datetime

from . import common
from .common import (SERVER_DEFAULT_ADDRESS, AUTH_KEY, Req, Rsp, Event, MyDataClass)
from ws_base import ClientBase, connect, handle_socketio_error, build_exception_map

log = logger.get_logger(__name__)


class Client(ClientBase):
    def __init__(self, server_url: str = SERVER_DEFAULT_ADDRESS, is_autoconnect: bool = False):
        super().__init__(server_url,
                         build_exception_map(common),
                         auth_data=AUTH_KEY,
                         ssl_verify=False,
                         is_autoconnect=is_autoconnect)

    def emit(self, event: Event, data: Union[int, float, str, List, Dict] = None) -> None:
        self.sio.emit(event, Req(event=event, data=data).to_dict())

    @connect
    @handle_socketio_error
    def get_value(self) -> Any:
        self.make_request(Req(Event.GET_VALUE))
        rsp = self._get_and_verify_response()
        return rsp.data

    @connect
    @handle_socketio_error
    def set_value(self, value: Any) -> Any:
        self.make_request(Req(Event.SET_VALUE, data=value))
        rsp = self._get_and_verify_response()
        return rsp.data

    @connect
    @handle_socketio_error
    def method(self, param: Any) -> Any:
        self.make_request(Req(Event.METHOD, data=param))
        rsp = self._get_and_verify_response()
        return rsp.data

    @connect
    @handle_socketio_error
    def get_dataclass(self) -> MyDataClass:
        self.make_request(Req(Event.GET_DATACLASS))
        rsp = self._get_and_verify_response()
        return MyDataClass.from_dict(rsp.data)

    def callbacks(self) -> None:
        @self.sio.event
        def connect() -> None:  # noqa
            log.info(f'Connection established with: {self.server_url} as: {self.sio.get_sid()} '
                     f'using transport: {self.sio.transport()}')

        @self.sio.event
        def disconnect() -> None:
            log.info(f'Disconnected from server: {self.server_url} as: {self.sio.get_sid()}')

        @self.handle_response()
        def get_value() -> None:
            log.debug(f'Received {self.rsp.event} from {self.server_url}')

        @self.handle_response()
        def set_value() -> None:
            log.debug(f'Received {self.rsp.event} from {self.server_url}')

        @self.handle_response()
        def method() -> None:
            log.debug(f'Received {self.rsp.event} from {self.server_url}')

        @self.handle_response()
        def get_dataclass() -> None:
            log.debug(f'Received {self.rsp.event} from {self.server_url}')
