#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
import requests
import functools
import inspect
import threading
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Optional, Type, Union, Tuple, List, Dict, Callable, Any, Awaitable
from datetime import UTC, datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

import socketio
from socketio.exceptions import SocketIOError
from gevent import pywsgi
from geventwebsocket.handler import WebSocketHandler


_log = logger.get_logger(__name__)


class WsBaseError(Exception):
    pass


class ResponseError(WsBaseError):
    def __init__(self, *args, tb: str) -> None:
        super().__init__(*args)
        self.tb = tb


class ResponseTimeoutError(WsBaseError):
    pass


@dataclass
class SerializableException:
    name: str
    message: str
    tb: str

    @classmethod
    def from_dict(cls, d) -> 'SerializableException':
        return cls(**d)

    def to_dict(self) -> Dict:
        return asdict(self)


class Status:
    SUCCESS = 'success'
    ERROR = 'error'


class Req(ABC):
    event: Any
    data: Any

    @classmethod
    @abstractmethod
    def from_dict(cls, d) -> 'Req':
        pass

    def to_dict(self) -> Dict:
        pass


@dataclass  # TODO: remove?
class Rsp(ABC):
    status: str
    event: Optional[Any] = None
    data: Optional[Any] = None

    @classmethod
    def from_dict(cls, d) -> 'Rsp':
        return cls(**d)

    def to_dict(self) -> Dict:
        return asdict(self)


class ClientBase(ABC):
    def __init__(self,
                 server_url: str,
                 exception_map: Dict,
                 auth_data: Any = None,
                 ssl_verify: bool = True,
                 is_autoconnect: bool = False) -> None:
        self._server_url = server_url
        self._exception_map = exception_map
        self.auth_data = auth_data
        self.ssl_verify = ssl_verify

        self.rsp = None
        self.rsp_event = threading.Event()
        self.sio: Optional[socketio.Client] = None
        if is_autoconnect:
            handle_socketio_error(self.connect)()

    @property
    def connected(self) -> bool:
        return self.sio is not None and self.sio.connected

    @property
    def server_url(self) -> str:
        return self._server_url

    def connect(self, url: str = None) -> None:
        connect(self, url=url)

    def disconnect(self) -> None:
        if self.connected:
            self.sio.disconnect()
            self.sio = None

    @abstractmethod
    def callbacks(self) -> None:
        pass

    def make_request(self, req: Req):
        self.sio.emit(req.event.req_event, req.to_dict())

    def handle_response(self) -> Callable:
        def decorator(func: Callable):
            event_name = func.__name__ + '_rsp'

            @functools.wraps(func)
            def wrapper(data):
                self.rsp = Rsp.from_dict(data)
                self.rsp_event.set()

            self.sio.on(event_name)(wrapper)
            return wrapper

        return decorator

    def _get_response(self, timeout: float = 5) -> Rsp:
        # TODO: probably there is a bug here, should be queue to avoid event overwrite
        self.rsp_event.wait(timeout=timeout)
        if not self.rsp_event.is_set():
            try:
                self.disconnect()
            finally:
                raise ResponseTimeoutError('Response timeout')
        self.rsp_event.clear()
        return self.rsp

    def _get_and_verify_response(self, timeout: float = 5) -> Rsp:
        rsp = self._get_response(timeout=timeout)
        self.verify_response(rsp)
        return rsp

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


class ServerBase(ABC):
    def __init__(self,
                 hostname: str,
                 port: int,
                 certfile: Optional[str] = None,
                 keyfile: Optional[str] = None) -> None:
        self.hostname = hostname
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

        self.sio: Optional[socketio.Server] = None
        self.app: Optional[socketio.WSGIApp] = None
        self.server: Optional[pywsgi.WSGIServer] = None

    @property
    def url(self) -> str:
        protocol = 'wss' if self.certfile else 'ws'
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
                self.callbacks()

                self.server = pywsgi.WSGIServer((self.hostname, self.port),
                                                self.app,
                                                handler_class=WebSocketHandler,
                                                **(dict(certfile=self.certfile,
                                                        keyfile=self.keyfile) if self.certfile else {}))
                self.server.serve_forever()
                _log.info('Server thread closed')
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

    def handle_request(self, req_cls: Type[Req]) -> Callable:
        def decorator(func: Callable):
            event_name = func.__name__ + '_req'

            @functools.wraps(func)
            def wrapper(sid, data):
                req = req_cls.from_dict(data)
                try:
                    rsp = func(sid, req.event, req.data)
                except Exception as e:
                    rsp = Rsp(status=Status.ERROR, data=SerializableException(name=e.__class__.__name__,
                                                                              message=str(e),
                                                                              tb=traceback.format_exc()).to_dict())
                rsp.event = req.event.rsp_event
                self.sio.emit(rsp.event, data=rsp.to_dict(), to=sid)

            self.sio.on(event_name)(wrapper)
            return wrapper

        return decorator

    def parse_req_and_send_rsp(self, req_cls: Type[Req]) -> Callable:
        def decorator(func: Callable):
            @functools.wraps(func)
            def wrapper(sid, data):
                req = req_cls.from_dict(data)
                rsp = func(sid, req.event, req.data)
                rsp.event = req.event.rsp_event
                self.sio.emit(rsp.event, data=rsp.to_dict(), to=sid)
            return wrapper
        return decorator

    @staticmethod
    def handle_errors(func) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Union[Callable, Rsp]:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                return Rsp(status=Status.ERROR, data=SerializableException(name=e.__class__.__name__,
                                                                           message=str(e),
                                                                           tb=traceback.format_exc()).to_dict())
        return wrapper

    @abstractmethod
    def callbacks(self) -> None:
        pass


def connect(*args, **kwargs):
    def _connect(self, url: str = None):
        if not self.connected:
            if self.sio is None:
                self.sio = socketio.Client(reconnection=True, request_timeout=1, ssl_verify=self.ssl_verify)
                self.callbacks()
            if url is not None:
                self._server_url = url
            handle_socketio_error(self.sio.connect)(self.server_url,
                                                    auth=self.auth_data,
                                                    wait=True,
                                                    wait_timeout=1)

    if inspect.isfunction(args[0]) or inspect.ismethod(args[0]):
        func = args[0]

        @functools.wraps(func)
        def wrapper(self, *w_args, **w_kwargs):
            _connect(self)
            return func(self, *w_args, **w_kwargs)

        return wrapper
    else:
        _connect(*args, **kwargs)


def handle_socketio_error(func) -> Callable:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SocketIOError as e:
            if 'ConnectionResetError' in str(e) and 'Connection reset by peer' in str(e):
                raise ConnectionError(f'Connection error, check url and server state: {e}')
            else:
                raise ConnectionError(e)

    return wrapper


def get_external_ip_address() -> str:
    return requests.get('http://ifconfig.me').text.strip()


def build_exception_map(module) -> Dict:
    return {
        name: obj
        for name, obj in inspect.getmembers(module)
        if inspect.isclass(obj) and issubclass(obj, BaseException)
    }


def generate_selfsigned_cert(hostname: str,
                             ip_addresses: Optional[List[str]] = None,
                             key: Optional[rsa.RSAPrivateKey] = None) -> Tuple[bytes, bytes]:
    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    alt_names = [x509.DNSName(hostname)]
    if ip_addresses:
        alt_names += [x509.DNSName(ip) for ip in ip_addresses]
    san = x509.SubjectAlternativeName(alt_names)
    basic_constraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365 * 10))
            .add_extension(basic_constraints, False)
            .add_extension(san, False)
            .sign(key, hashes.SHA256(), default_backend()))
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption())

    return cert_pem, key_pem


def get_dns_names_from_cert(pem_cert_data: bytes) -> List[str]:
    cert = x509.load_pem_x509_certificate(pem_cert_data)
    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    return ext.value.get_values_for_type(x509.DNSName)
