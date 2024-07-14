#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import hashlib
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum, StrEnum, auto
from typing import Optional, Union, List, Dict
from decimal import Decimal

import ws_base as wsbase  # TODO: rename


SERVER_DEFAULT_HOST = 'localhost'
SERVER_DEFAULT_PORT = 9000
SERVER_DEFAULT_URL = f'wss://{SERVER_DEFAULT_HOST}:{SERVER_DEFAULT_PORT}'
PACKAGE_PATH = Path(__file__).parent
AUTH_KEY = hashlib.sha3_256(f'<<## {PACKAGE_PATH.name} auth key ##>>'.encode()).hexdigest()


class MyError(Exception):
    pass


class Event(wsbase.Event, StrEnum):
    GET_VALUE = auto()
    SET_VALUE = auto()
    METHOD = auto()
    GET_DATACLASS = auto()


class Status(wsbase.Status, StrEnum):
    pass


# TODO: move
class SerializableDataClass:
    @classmethod
    def from_dict(cls, d) -> 'SerializableDataClass':
        obj = cls(**d)  # noqa
        if 'event' in d and hasattr(obj, 'event'):
            obj.event = Event(obj.event)
        return obj

    def to_dict(self) -> Dict:
        d = asdict(self)  # noqa
        for key, value in d.items():
            if isinstance(value, Enum):
                d[key] = value.value
            if isinstance(value, Decimal):
                d[key] = str(value)
        return d

    @classmethod
    def from_json(cls, json_str: str) -> 'SerializableDataClass':
        return cls.from_dict(json.loads(json_str))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4)


@dataclass
class Req(SerializableDataClass, wsbase.Req):
    event: Event
    data: Optional[Union[int, float, str, List, Dict]] = None


@dataclass
class Rsp(SerializableDataClass, wsbase.Rsp):
    status: Status
    event: Optional[Event] = None
    data: Optional[Union[int, float, str, List, Dict]] = None


@dataclass
class MyDataClass(SerializableDataClass):
    value1: Decimal
    value2: str
    kvalue1: int = 1
    kvalue2: str = 'kvalue'

    @classmethod
    def from_dict(cls, d) -> 'MyDataClass':
        obj = super().from_dict(d)
        obj.value1 = Decimal(obj.value1)
        return obj
