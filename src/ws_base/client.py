#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
import functools
import inspect
import threading
from abc import ABC, abstractmethod
from typing import Optional, Dict, Callable, Any

import socketio
from socketio.exceptions import SocketIOError

from .ws_base import (Rsp, Req, Status, SerializableException, ResponseError, ResponseTimeoutError,
                      get_req_event, handle_socketio_error)

log = logger.get_logger(__name__)


class ClientBase(ABC):
    def __init__(self,
                 server_url: str,
                 exception_map: Dict,
                 auth_data: Any = None,
                 ssl_verify: bool = True,
                 is_autoconnect: bool = False,
                 timeout: float = 3.0,
                 retries: int = 3) -> None:
        self._server_url = server_url
        self._exception_map = exception_map
        self.auth_data = auth_data
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.retries = retries

        self.rsp = None
        self.sio: Optional[socketio.Client] = None
        self.lock = threading.Lock()
        self.req_seq = 0
        self.pending_responses = {}
        if is_autoconnect:
            handle_socketio_error(self.connect)()

    @property
    def connected(self) -> bool:
        return self.sio is not None and self.sio.connected

    @property
    def server_url(self) -> str:
        return self._server_url

    @property
    def sid(self) -> str:
        return self.sio.sid

    def connect(self, url: Optional[str] = None) -> None:
        connect(self, url=url)

    def disconnect(self) -> None:
        with self.lock:
            if self.connected:
                self.sio.disconnect()
                self.sio = None

    def connection_callbacks(self) -> None:
        @self.sio.event
        def connect() -> None:  # noqa
            log.info(f'Connection established with: {self.server_url} as: {self.sio.get_sid()} '
                     f'using transport: {self.sio.transport()}')

        @self.sio.event
        def disconnect() -> None:
            log.info(f'{self.sio.get_sid()} disconnected from server')

        @self.sio.event
        def connect_error(msg) -> None:
            log.error(f'Failed to connect to server: {msg}')

    @abstractmethod
    def callbacks(self) -> None:
        pass

    @handle_socketio_error
    def make_request(self, req: Req, timeout: Optional[float] = None) -> Rsp:
        reconnect = False
        for retry in range(1, self.retries + 2):
            try:
                if reconnect:
                    reconnect = False
                    self.connect()
                    log.warning(f'Client reconnected with sid: {self.sio}')
                return self._make_request(req, timeout=timeout or self.timeout)
            except (ConnectionError, ConnectionResetError, SocketIOError, ResponseTimeoutError) as e:
                if retry <= self.retries:
                    log.warning(f'Request error: {e}. Retry {retry} of {self.retries}')
                    if not self.connected:
                        reconnect = True
                    continue
                else:
                    raise

    def _make_request(self, req: Req, timeout: float) -> Rsp:
        with self.lock:
            req.id = self.req_seq
            self.req_seq += 1
            event = threading.Event()
            self.pending_responses[req.id] = (event, None)
            log.debug(f'Make request: {req}')
            self.sio.emit(get_req_event(req.event), req.to_dict())

        if not event.wait(timeout):
            raise ResponseTimeoutError('Response timeout')

        with self.lock:
            rsp = self.pending_responses.pop(req.id)[1]
        if rsp is None:
            raise ResponseTimeoutError('Response received but was None')

        return rsp

    def handle_response(self) -> Callable:
        def decorator(func: Callable):
            event_name = func.__name__ + '_rsp'

            @functools.wraps(func)
            def wrapper(data: Dict):
                rsp_data = {key: (value[:-4] if key == 'event' else value) for key, value in data.items()}
                rsp = Rsp.from_dict(rsp_data)
                with self.lock:
                    if rsp.id in self.pending_responses:
                        event, _ = self.pending_responses[rsp.id]
                        self.pending_responses[rsp.id] = (event, rsp)
                        event.set()

            self.sio.on(event_name)(wrapper)
            return wrapper

        return decorator

    def verify_response(self, rsp: Rsp) -> None:
        if rsp.status != Status.SUCCESS:
            exception = SerializableException.from_dict(rsp.data)
            exception_class = self._exception_map.get(exception.name)
            if exception_class:
                exc = exception_class(exception.message)
                exc.tb = exception.tb
                exc.event = rsp.event
                raise exc
            else:
                raise ResponseError(f'Error: {exception.name}, message: {exception.message}, event: {rsp.event}',
                                    tb=exception.tb)


def connect(*args, **kwargs):
    def _connect(self, url: str = None) -> None:
        with self.lock:
            if not self.connected:
                if self.sio is None:
                    self.sio = socketio.Client(reconnection=True, request_timeout=1, ssl_verify=self.ssl_verify)
                    self.connection_callbacks()
                    self.callbacks()
                if url is not None:
                    self._server_url = url
                try:
                    handle_socketio_error(self.sio.connect)(self.server_url,
                                                            auth=self.auth_data,
                                                            wait=True,
                                                            wait_timeout=1)
                except ValueError as e:
                    if 'not in a disconnected state' in str(e):
                        pass
                    else:
                        raise

    if inspect.isfunction(args[0]) or inspect.ismethod(args[0]):
        func = args[0]

        @functools.wraps(func)
        def wrapper(self, *w_args, **w_kwargs) -> Any:
            _connect(self)
            return func(self, *w_args, **w_kwargs)

        return wrapper
    else:
        _connect(*args, **kwargs)
