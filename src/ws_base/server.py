#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ssl
import asyncio
import logger
import functools
import threading
import traceback
import aiohttp.web
import socketio
from socketio.exceptions import SocketIOError
from abc import ABC, abstractmethod
from typing import Optional, Union, Callable, List, Dict
from pathlib import Path
from urllib.parse import urlparse

from .common import (Rsp, Req, Status, SerializableException, get_rsp_event, generate_new_cert,
                     get_dns_names_from_cert, get_public_ip_address)

log = logger.get_logger(__name__)


class BaseServer(ABC, threading.Thread):
    def __init__(self,
                 hostname: Optional[str] = None,
                 port: Optional[int] = None,
                 url: Optional[str] = None,
                 certfile_path: Optional[Path] = None,
                 keyfile_path: Optional[Path] = None,
                 generate_cert: bool = True,
                 auth_data: Optional[Union[str, Dict]] = None,
                 ping_interval: int = 25,
                 ping_timeout: int = 5) -> None:
        super().__init__()

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
        self.auth_data = auth_data
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout

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
        self.app: Optional[aiohttp.web.Application] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.loop_ready = threading.Event()
        self._exit_event = asyncio.Event()
        self._runner: Optional[aiohttp.web.AppRunner] = None

    @property
    def url(self) -> str:
        protocol = 'wss' if self.certfile_path else 'ws'
        return f'{protocol}://{self.hostname}:{self.port}'

    @property
    def started(self) -> bool:
        return self._runner is not None

    @property
    def connections(self) -> List[str]:
        try:
            return list(filter(lambda x: x is not None, self.sio.manager.rooms['/']))
        except (KeyError, AttributeError):
            return []

    def start(self) -> None:
        if self.started:
            raise RuntimeError('Server already started')

        super().start()
        self.loop_ready.wait()
        asyncio.run_coroutine_threadsafe(self._start(), self.loop).result()
        wait_event = threading.Event()
        while not self.started:
            wait_event.wait(timeout=0.1)

    async def _start(self) -> None:
        cors_allowed_origins = [
            f'http://{self.hostname}:{self.port}',
            f'https://{self.hostname}:{self.port}'
        ]
        external_ip_address = await get_public_ip_address()
        if external_ip_address != self.hostname:
            cors_allowed_origins += [
                f'http://{external_ip_address}:{self.port}',
                f'https://{external_ip_address}:{self.port}'
            ]
        self.sio = socketio.AsyncServer(async_mode='aiohttp',
                                        ping_interval=self.ping_interval,
                                        ping_timeout=self.ping_timeout,
                                        cors_allowed_origins=cors_allowed_origins)
        self.app = aiohttp.web.Application()
        self.sio.attach(self.app)
        self.connection_callbacks()
        self.callbacks()

        ssl_context = None
        if self.certfile_path and self.keyfile_path:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=self.certfile_path, keyfile=self.keyfile_path)

        runner = aiohttp.web.AppRunner(self.app, shutdown_timeout=1)
        await runner.setup()
        site = aiohttp.web.TCPSite(runner, self.hostname, self.port, ssl_context=ssl_context)
        await site.start()

        self._runner = runner

    def close(self) -> None:
        self._exit_event.set()
        self.join()

    def run(self) -> None:
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self._main())
        except Exception as e:
            log.exception(e)
        finally:
            self.loop.close()
            log.info('Server thread closed')

    async def _main(self) -> None:
        self.loop_ready.set()

        # Here sleep is used instead of wait on event due to some lags with event state change.
        while not self._exit_event.is_set():
            await asyncio.sleep(0.1)

        if self._runner:
            await self._runner.cleanup()
            self._runner = None

        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def handle_request(self) -> Callable:
        def decorator(func: Callable):
            event_name = func.__name__ + '_req'

            @functools.wraps(func)
            async def wrapper(sid, data):
                req = Req.from_dict(data)
                try:
                    rsp = await func(sid, req.event, req.data)
                except Exception as e:
                    rsp = Rsp(status=Status.ERROR, data=SerializableException(name=e.__class__.__name__,
                                                                              message=str(e),
                                                                              tb=traceback.format_exc()).to_dict())
                rsp.event = get_rsp_event(req.event)
                rsp.id = req.id
                await self.sio.emit(rsp.event, data=rsp.to_dict(), to=sid)

            self.sio.on(event_name, wrapper)
            return wrapper

        return decorator

    def connection_callbacks(self) -> None:
        @self.sio.event
        def connect(sid, _, auth) -> None:  # noqa
            log.info(f'Connect client: {sid}')
            if auth != self.auth_data:
                raise socketio.exceptions.ConnectionRefusedError('Authentication failed')

        @self.sio.event
        def disconnect(sid) -> None:
            log.info(f'Disconnect client: {sid}')

    @abstractmethod
    def callbacks(self) -> None:
        pass
