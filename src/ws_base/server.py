#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
import functools
import threading
import traceback
from abc import ABC, abstractmethod
from typing import Optional, Callable
from pathlib import Path
from urllib.parse import urlparse

import socketio
from socketio.exceptions import SocketIOError
from gevent import pywsgi
from geventwebsocket.handler import WebSocketHandler

from .ws_base import (Rsp, Req, Status, SerializableException, get_rsp_event, generate_new_cert,
                      get_dns_names_from_cert, get_external_ip_address)

log = logger.get_logger(__name__)


class ServerBase(ABC):
    def __init__(self,
                 hostname: Optional[str] = None,
                 port: Optional[int] = None,
                 url: Optional[str] = None,
                 certfile_path: Optional[Path] = None,
                 keyfile_path: Optional[Path] = None,
                 generate_cert: bool = True,
                 auth_key: Optional[str] = None) -> None:
        if url:
            if hostname or port:
                raise ValueError('You cannot specify both URL and hostname or port')

            self.hostname = urlparse(url).hostname
            self.port = urlparse(url).port
        else:
            if url:
                raise ValueError('You cannot specify both URL and hostname or port')
            self.hostname = hostname
            self.port = port

        if not self.hostname or not self.port:
            raise ValueError('Both hostname and port must be specified either directly or via the URL')

        self.certfile_path = certfile_path
        self.keyfile_path = keyfile_path
        self.auth_key = auth_key

        if generate_cert:
            if not self.certfile_path.exists() or not self.keyfile_path.exists():
                log.info(f'Generating a new SSL certificate for hostname: {self.hostname}')
                generate_new_cert(self.certfile_path, self.keyfile_path, self.hostname)
            else:
                dns_names = get_dns_names_from_cert(self.certfile_path.read_bytes())
                if self.hostname not in dns_names:
                    log.info(f'Incompatible SSL certificate. Generating a new for hostname: {self.hostname}')
                    generate_new_cert(self.certfile_path, self.keyfile_path, self.hostname)

        self.sio: Optional[socketio.Server] = None
        self.app: Optional[socketio.WSGIApp] = None
        self.server: Optional[pywsgi.WSGIServer] = None

    @property
    def url(self) -> str:
        protocol = 'wss' if self.certfile_path else 'ws'
        return f'{protocol}://{self.hostname}:{self.port}'

    @property
    def started(self) -> bool:
        return self.server is not None and self.server.started

    def start(self) -> None:
        exc = None

        def start_server():
            try:
                cors_allowed_origins = [
                    f'http://{self.hostname}:{self.port}',
                    f'https://{self.hostname}:{self.port}'
                ]
                external_ip_address = get_external_ip_address()
                if external_ip_address != self.hostname:
                    cors_allowed_origins += [
                        f'http://{external_ip_address}:{self.port}',
                        f'https://{external_ip_address}:{self.port}'
                    ]
                self.sio = socketio.Server(async_mode='gevent',
                                           ping_interval=25,
                                           ping_timeout=5,
                                           cors_allowed_origins=cors_allowed_origins)
                self.app = socketio.WSGIApp(self.sio)
                self.connection_callbacks()
                self.callbacks()

                self.server = pywsgi.WSGIServer((self.hostname, self.port),
                                                self.app,
                                                handler_class=WebSocketHandler,
                                                **(dict(certfile=self.certfile_path,
                                                        keyfile=self.keyfile_path) if self.certfile_path else {}))
                self.server.serve_forever()
                log.info('Server thread closed')
            except Exception as e:
                nonlocal exc
                exc = e

        threading.Thread(target=start_server, daemon=True).start()

        wait_event = threading.Event()
        while not self.started:
            if exc:
                raise exc
            wait_event.wait(timeout=0.1)

    def join(self) -> None:
        wait_event = threading.Event()
        while self.server and self.server.started:
            wait_event.wait(timeout=0.1)

    def close(self) -> None:
        self.server.close()
        self.join()
        self.server = None

    def handle_request(self) -> Callable:
        def decorator(func: Callable):
            event_name = func.__name__ + '_req'

            @functools.wraps(func)
            def wrapper(sid, data):
                req = Req.from_dict(data)
                try:
                    rsp = func(sid, req.event, req.data)
                except Exception as e:
                    rsp = Rsp(status=Status.ERROR, data=SerializableException(name=e.__class__.__name__,
                                                                              message=str(e),
                                                                              tb=traceback.format_exc()).to_dict())
                rsp.event = get_rsp_event(req.event)
                rsp.id = req.id
                self.sio.emit(rsp.event, data=rsp.to_dict(), to=sid)

            self.sio.on(event_name)(wrapper)
            return wrapper

        return decorator

    def connection_callbacks(self) -> None:
        @self.sio.event
        def connect(sid, _, auth) -> None:  # noqa
            log.info(f'Connect client: {sid}')
            if auth != self.auth_key:
                raise socketio.exceptions.ConnectionRefusedError('Authentication failed')

        @self.sio.event
        def disconnect(sid) -> None:
            log.info(f'Disconnect client: {sid}')

    @abstractmethod
    def callbacks(self) -> None:
        pass
