#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logger
import functools
import inspect
import aiohttp
from abc import ABC
from dataclasses import dataclass, asdict
from typing import Optional, Union, Tuple, List, Dict, Callable, Any
from datetime import UTC, datetime, timedelta
from pathlib import Path
from pydantic import RootModel, BaseModel
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from socketio.exceptions import SocketIOError

log = logger.get_logger(__name__)


class WsBaseError(Exception):
    pass


class ResponseError(WsBaseError):
    def __init__(self, *args, tb: str) -> None:
        super().__init__(*args)
        self.tb = tb


class ResponseTimeoutError(WsBaseError):
    pass


class SerializableBaseModel(BaseModel):
    @classmethod
    def from_json(cls, json_str: str) -> 'SerializableBaseModel':
        return cls.model_validate_json(json_str)

    def to_json(self, indent: Optional[int] = None) -> str:
        return self.model_dump_json(indent=indent)


class SerializableDataClass:
    @classmethod
    def from_json(cls, json_str: str) -> 'SerializableDataClass':
        return RootModel[cls].model_validate_json(json_str).root

    def to_json(self, indent: Optional[int] = None) -> str:
        return RootModel[self.__class__](self).model_dump_json(indent=indent)


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


def get_req_event(event: str) -> str:
    return event + '_req'


def get_rsp_event(event: str) -> str:
    return event + '_rsp'


@dataclass
class Req(ABC):
    event: Any
    data: Optional[Union[int, float, str, List, Dict, SerializableDataClass, SerializableBaseModel]] = None
    id: int = 0

    @classmethod
    def from_dict(cls, d) -> 'Req':
        obj = cls(**d)
        return obj

    def to_dict(self) -> Dict:
        if isinstance(self.data, SerializableDataClass) or isinstance(self.data, SerializableBaseModel):
            return {'event': str(self.event), 'data': self.data.to_json(), 'id': self.id}
        return asdict(self)


@dataclass
class Rsp(ABC):
    status: str
    event: Optional[Any] = None
    data: Optional[Union[int, float, str, List, Dict, SerializableDataClass, SerializableBaseModel]] = None
    id: int = 0

    @classmethod
    def from_dict(cls, d) -> 'Rsp':
        obj = cls(**d)
        return obj

    def to_dict(self) -> Dict:
        if isinstance(self.data, SerializableDataClass) or isinstance(self.data, SerializableBaseModel):
            return {'status': self.status, 'event': str(self.event), 'data': self.data.to_json(), 'id': self.id}
        return asdict(self)


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


async def get_external_ip_address() -> str:
    async with aiohttp.request('GET', 'http://ifconfig.me/ip') as response:
        return (await response.text()).strip()


def build_exception_map(module) -> Dict:
    return {
        name: obj
        for name, obj in inspect.getmembers(module)
        if inspect.isclass(obj) and issubclass(obj, BaseException)
    }


def generate_new_cert(certfile_path: Path, keyfile_path: Path, hostname: str) -> None:
    cert_pem, key_pem = generate_selfsigned_cert(hostname=hostname)
    certfile_path.parent.mkdir(parents=True, exist_ok=True)
    certfile_path.write_bytes(cert_pem)
    keyfile_path.write_bytes(key_pem)


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
