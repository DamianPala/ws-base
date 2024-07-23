#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib
from pathlib import Path
from dataclasses import dataclass
from enum import StrEnum, auto
from typing import List
from decimal import Decimal
import ws_base as wsbase  # TODO: rename


SERVER_DEFAULT_HOST = 'localhost'
SERVER_DEFAULT_PORT = 9000
SERVER_DEFAULT_URL = f'wss://{SERVER_DEFAULT_HOST}:{SERVER_DEFAULT_PORT}'
PACKAGE_PATH = Path(__file__).parent
AUTH_KEY = hashlib.sha3_256(f'<<## {PACKAGE_PATH.name} auth key ##>>'.encode()).hexdigest()


class MyError(Exception):
    pass


class Event(StrEnum):
    GET_VALUE = auto()
    SET_VALUE = auto()
    METHOD = auto()
    GET_DATACLASS = auto()
    SET_DATACLASS = auto()
    GET_BASEMODEL = auto()
    SET_BASEMODEL = auto()
    INCREMENT = auto()


class SubClassBase(wsbase.SerializableBaseModel):
    value: Decimal


class MainClassBase(wsbase.SerializableBaseModel):
    id: int
    name: str
    values: List[Decimal]
    nested: SubClassBase


@dataclass
class SubClassData(wsbase.SerializableDataClass):
    value: Decimal


@dataclass
class MainClassData(wsbase.SerializableDataClass):
    id: int
    name: str
    values: List[Decimal]
    nested: SubClassData
