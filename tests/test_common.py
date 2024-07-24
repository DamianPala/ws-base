#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logger
from decimal import Decimal
from tests.clientserver import MainClassData, SubClassData, MainClassBase, SubClassBase

log = logger.get_logger(__name__)


def test_serialize_deserialize_basemodel():
    basemodel = MainClassBase(
        id=1, name="Example", values=[Decimal('1.1'), Decimal('2.2')], nested=SubClassBase(value=Decimal('10.5'))
    )

    d = basemodel.to_dict(mode='python')
    obj = MainClassBase.from_dict(d)
    assert obj == basemodel

    d = basemodel.to_dict(mode='json')
    obj = MainClassBase.from_dict(d)
    assert obj == basemodel

    jn = basemodel.to_json()
    obj = MainClassBase.from_json(jn)
    assert obj == basemodel


def test_serialize_deserialize_dataclass():
    dataclass = MainClassData(
        id=1, name="Example", values=[Decimal('1.1'), Decimal('2.2')], nested=SubClassData(value=Decimal('10.5'))
    )

    d = dataclass.to_dict(mode='python')
    obj = MainClassData.from_dict(d)
    assert obj == dataclass

    d = dataclass.to_dict(mode='json')
    obj = MainClassData.from_dict(d)
    assert obj == dataclass

    jn = dataclass.to_json()
    obj = MainClassData.from_json(jn)
    assert obj == dataclass
