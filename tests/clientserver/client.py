#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
from typing import Any
from ws_base import Req, BaseClient, connect, build_exception_map

from . import common
from .common import (SERVER_DEFAULT_URL, AUTH_KEY, Event, MainClassData, MainClassBase)

log = logger.get_logger(__name__)


class Client(BaseClient):
    def __init__(self, server_url: str = SERVER_DEFAULT_URL, is_autoconnect: bool = False):
        super().__init__(server_url,
                         build_exception_map(common),
                         auth_data=AUTH_KEY,
                         ssl_verify=False,
                         is_autoconnect=is_autoconnect)

    @connect
    def get_value(self) -> Any:
        rsp = self.make_request(Req(Event.GET_VALUE))
        self.verify_response(rsp)
        return rsp.data

    @connect
    def set_value(self, value: Any) -> Any:
        rsp = self.make_request(Req(Event.SET_VALUE, data=value))
        self.verify_response(rsp)
        return rsp.data

    @connect
    def method(self, param: Any) -> Any:
        rsp = self.make_request(Req(Event.METHOD, data=param))
        self.verify_response(rsp)
        return rsp.data

    @connect
    def get_dataclass(self) -> MainClassData:
        rsp = self.make_request(Req(Event.GET_DATACLASS))
        self.verify_response(rsp)
        return MainClassData.from_json(rsp.data)

    @connect
    def set_dataclass(self, value: MainClassData) -> MainClassData:
        rsp = self.make_request(Req(Event.SET_DATACLASS, data=value))
        self.verify_response(rsp)
        return MainClassData.from_json(rsp.data)

    @connect
    def get_basemodel(self) -> MainClassBase:
        rsp = self.make_request(Req(Event.GET_BASEMODEL))
        self.verify_response(rsp)
        return MainClassBase.from_json(rsp.data)

    @connect
    def set_basemodel(self, value: MainClassBase) -> MainClassBase:
        rsp = self.make_request(Req(Event.SET_BASEMODEL, data=value))
        self.verify_response(rsp)
        return MainClassBase.from_json(rsp.data)

    @connect
    def increment(self, value: int) -> int:
        rsp = self.make_request(Req(Event.INCREMENT, data=value))
        self.verify_response(rsp)
        return rsp.data

    def callbacks(self) -> None:
        @self.handle_response()
        def get_value(_) -> None:
            pass

        @self.handle_response()
        def set_value(_) -> None:
            pass

        @self.handle_response()
        def method(rsp) -> None:
            log.info(f'Method called with rsp: {rsp}')

        @self.handle_response()
        def get_dataclass(_) -> None:
            pass

        @self.handle_response()
        def set_dataclass(_) -> None:
            pass

        @self.handle_response()
        def get_basemodel(_) -> None:
            pass

        @self.handle_response()
        def set_basemodel(_) -> None:
            pass

        @self.handle_response()
        def increment(_) -> None:
            pass
