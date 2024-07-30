#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import List
from decimal import Decimal
from wsbase import SerializableDataClass, SerializableBaseModel


SERVER_DEFAULT_HOST = 'localhost'
SERVER_DEFAULT_PORT = 9000
SERVER_DEFAULT_URL = f'wss://{SERVER_DEFAULT_HOST}:{SERVER_DEFAULT_PORT}'
PACKAGE_PATH = Path(__file__).parent
AUTH_KEY = hashlib.sha3_256(f'<<## {PACKAGE_PATH.name} auth key ##>>'.encode()).hexdigest()


class MyError(Exception):
    pass


class Event:
    """For Python>=3.11 use StrEnum GET_VALUE = auto()"""
    
    GET_VALUE = 'get_value'
    SET_VALUE = 'set_value'
    METHOD = 'method'
    GET_DATACLASS = 'get_dataclass'
    SET_DATACLASS = 'set_dataclass'
    GET_BASEMODEL = 'get_basemodel'
    SET_BASEMODEL = 'set_basemodel'
    INCREMENT = 'increment'


class SubClassBase(SerializableBaseModel):
    value: Decimal


class MainClassBase(SerializableBaseModel):
    id: int
    name: str
    values: List[Decimal]
    nested: SubClassBase


@dataclass
class SubClassData(SerializableDataClass):
    value: Decimal


@dataclass
class MainClassData(SerializableDataClass):
    id: int
    name: str
    values: List[Decimal]
    nested: SubClassData
