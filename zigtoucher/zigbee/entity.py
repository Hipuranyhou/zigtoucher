from __future__ import annotations
from typing import Dict, Union
import hashlib
import logging
import random
import secrets
import string
import tabulate
import termcolor


logger = logging.getLogger("zigtoucher.zigbee.entity")


class NwkAddr:
    """Int wrapper for short address."""

    BITS: int = 16
    COORDINATOR: int = 0x0000
    INITIATOR: int = 0x0001
    MAX: int = 0xFFF7
    NO: int = 0xFFFF
    HEADER: str = "NwkAddr"

    def __init__(self, nwk_addr: int = None) -> None:
        self.__nwk_addr = nwk_addr

    def __str__(self) -> str:
        return f"0x{self.__nwk_addr:04x}" if self.__nwk_addr is not None else "None"

    def __bool__(self) -> bool:
        return self.__nwk_addr is not None

    def __eq__(self, other) -> bool:
        if other is None:
            if self.__nwk_addr is None:
                return True
            else:
                return False
        if isinstance(other, NwkAddr):
            return self.__nwk_addr == other.__nwk_addr
        if isinstance(other, int):
            return self.__nwk_addr == other
        raise NotImplemented

    def __ne__(self, other) -> bool:
        return not (self == other)

    def get(self) -> int:
        return self.__nwk_addr

    def set(self, nwk_addr: int = None) -> None:
        self.__nwk_addr = nwk_addr

    @staticmethod
    def __is_usable(nwk_addr: int) -> bool:
        return nwk_addr <= NwkAddr.MAX

    @staticmethod
    def is_usable(nwk_addr: NwkAddr) -> bool:
        return NwkAddr.__is_usable(nwk_addr.get())

    @staticmethod
    def get_usable() -> NwkAddr:
        nwk_addr = random.getrandbits(NwkAddr.BITS)
        while not NwkAddr.__is_usable(nwk_addr):
            nwk_addr = random.getrandbits(NwkAddr.BITS)
        return NwkAddr(nwk_addr)

    @staticmethod
    def from_str(nwk_addr: str, random_ok: bool = True) -> NwkAddr:
        if not nwk_addr:
            raise ValueError("cannot be empty")
        nwk_addr = nwk_addr.lower()
        if nwk_addr == "<random>":
            if random_ok:
                return NwkAddr.get_usable()
            else:
                raise ValueError("invalid")
        if nwk_addr.startswith("0x"):
            nwk_addr = nwk_addr[2:]
        if len(nwk_addr) > 4:
            raise ValueError("too long")
        nwk_addr = int(nwk_addr, 16)
        if not NwkAddr.__is_usable(nwk_addr):
            raise ValueError("not usable")
        return NwkAddr(nwk_addr)


class IEEEAddr:
    """Int wrapper for IEEE address."""

    BITS: int = 64
    NO: int = 0x0000000000000000
    RESERVED: int = 0xFFFFFFFFFFFFFFFF
    HEADER: str = "IEEEAddr"

    def __init__(self, ieee_addr: int = None) -> None:
        self.__ieee_addr = ieee_addr

    def __str__(self) -> str:
        return (
            self.__ieee_addr.to_bytes(8, "big").hex(":")
            if self.__ieee_addr is not None
            else "None"
        )

    def __bool__(self) -> bool:
        return self.__ieee_addr is not None

    def __eq__(self, other) -> bool:
        if other is None:
            if self.__ieee_addr is None:
                return True
            else:
                return False
        if isinstance(other, IEEEAddr):
            return self.__ieee_addr == other.__ieee_addr
        if isinstance(other, int):
            return self.__ieee_addr == other
        raise NotImplemented

    def __ne__(self, other) -> bool:
        return not (self == other)

    def get(self) -> int:
        return self.__ieee_addr

    def set(self, ieee_addr: int = None) -> None:
        self.__ieee_addr = ieee_addr

    @staticmethod
    def __is_usable(ieee_addr: int) -> bool:
        return ieee_addr > IEEEAddr.NO and ieee_addr < IEEEAddr.RESERVED

    @staticmethod
    def is_usable(ieee_addr: IEEEAddr) -> bool:
        return IEEEAddr.__is_usable(ieee_addr.get())

    @staticmethod
    def get_usable() -> IEEEAddr:
        ieee_addr = random.getrandbits(IEEEAddr.BITS)
        while not IEEEAddr.__is_usable(ieee_addr):
            ieee_addr = random.getrandbits(IEEEAddr.BITS)
        return IEEEAddr(ieee_addr)

    @staticmethod
    def from_str(ieee_addr: str, random_ok: bool = True) -> IEEEAddr:
        if not ieee_addr:
            raise ValueError("cannot be empty")
        ieee_addr = ieee_addr.lower()
        if ieee_addr == "<random>":
            if random_ok:
                return IEEEAddr.get_usable()
            else:
                raise ValueError("invalid")
        ieee_addr = ieee_addr.replace(":", "")
        if len(ieee_addr) != 16:
            raise ValueError("must be 64-bit")
        ieee_addr = int(ieee_addr, 16)
        if not IEEEAddr.__is_usable(ieee_addr):
            raise ValueError("not usable")
        return IEEEAddr(ieee_addr)


class PanID:
    """Int wrapper for PAN ID."""

    BITS: int = 16
    MIN: int = 0x0000
    # MAX: int = 0x3FFF not everyone follows this
    MAX: int = 0xFFF7
    HEADER: str = "PanID"

    def __init__(self, pan_id: int = None) -> None:
        self.__pan_id = pan_id

    def __str__(self) -> str:
        return f"0x{self.__pan_id:04x}" if self.__pan_id is not None else "None"

    def __bool__(self) -> bool:
        return self.__pan_id is not None

    def __eq__(self, other) -> bool:
        if other is None:
            if self.__pan_id is None:
                return True
            else:
                return False
        if isinstance(other, PanID):
            return self.__pan_id == other.__pan_id
        if isinstance(other, int):
            return self.__pan_id == other
        raise NotImplemented

    def __ne__(self, other) -> bool:
        return not (self == other)

    def get(self) -> int:
        return self.__pan_id

    def set(self, pan_id: int = None) -> None:
        self.__pan_id = pan_id

    @staticmethod
    def __is_usable(pan_id: int) -> bool:
        return pan_id >= PanID.MIN and pan_id <= PanID.MAX

    @staticmethod
    def is_usable(pan_id: PanID) -> bool:
        return PanID.__is_usable(pan_id.get())

    @staticmethod
    def get_usable() -> PanID:
        pan_id = random.getrandbits(PanID.BITS)
        while not PanID.__is_usable(pan_id):
            pan_id = random.getrandbits(PanID.BITS)
        return PanID(pan_id)

    @staticmethod
    def from_str(pan_id: str, random_ok: bool = True) -> PanID:
        if not pan_id:
            raise ValueError("cannot be empty")
        pan_id = pan_id.lower()
        if pan_id == "<random>":
            if random_ok:
                return PanID.get_usable()
            else:
                raise ValueError("invalid")
        if pan_id.startswith("0x"):
            pan_id = pan_id[2:]
        if len(pan_id) > 4:
            raise ValueError("too long")
        pan_id = int(pan_id, 16)
        if not PanID.__is_usable(pan_id):
            raise ValueError("not usable")
        return PanID(pan_id)


class ExtPanID:
    """Int wrapper for extended PAN ID."""

    BITS: int = 64
    NO: int = 0x0000000000000000
    RESERVED: int = 0xFFFFFFFFFFFFFFFF
    HEADER: str = "ExtPanID"

    def __init__(self, ext_pan_id: int = None) -> None:
        self.__ext_pan_id = ext_pan_id

    def __str__(self) -> str:
        return (
            self.__ext_pan_id.to_bytes(8, "big").hex(":")
            if self.__ext_pan_id is not None
            else "None"
        )

    def __bool__(self) -> bool:
        return self.__ext_pan_id is not None

    def __eq__(self, other) -> bool:
        if other is None:
            if self.__ext_pan_id is None:
                return True
            else:
                return False
        if isinstance(other, ExtPanID):
            return self.__ext_pan_id == other.__ext_pan_id
        if isinstance(other, int):
            return self.__ext_pan_id == other
        raise NotImplemented

    def __ne__(self, other) -> bool:
        return not (self == other)

    def get(self) -> int:
        return self.__ext_pan_id

    def set(self, ext_pan_id: int = None) -> None:
        self.__ext_pan_id = ext_pan_id

    @staticmethod
    def __is_usable(ext_pan_id: int) -> bool:
        return ext_pan_id > ExtPanID.NO and ext_pan_id < ExtPanID.RESERVED

    @staticmethod
    def is_usable(ext_pan_id: ExtPanID) -> bool:
        return ExtPanID.__is_usable(ext_pan_id.get())

    @staticmethod
    def get_usable() -> ExtPanID:
        ext_pan_id = random.getrandbits(ExtPanID.BITS)
        while not ExtPanID.__is_usable(ext_pan_id):
            ext_pan_id = random.getrandbits(ExtPanID.BITS)
        return ExtPanID(ext_pan_id)

    @staticmethod
    def from_str(ext_pan_id: str, random_ok: bool = True) -> ExtPanID:
        if not ext_pan_id:
            raise ValueError("cannot be empty")
        ext_pan_id = ext_pan_id.lower()
        if ext_pan_id == "<random>":
            if random_ok:
                return ExtPanID.get_usable()
            else:
                raise ValueError("invalid")
        ext_pan_id = ext_pan_id.replace(":", "")
        if len(ext_pan_id) != 16:
            raise ValueError("must be 64-bit")
        ext_pan_id = int(ext_pan_id, 16)
        if not ExtPanID.__is_usable(ext_pan_id):
            raise ValueError("not usable")
        return ExtPanID(ext_pan_id)


class Channel:
    """Int wrapper for ZigBee channel."""

    MIN: int = 11
    MAX: int = 26
    PRIMARY: list = [11, 15, 20, 25]
    SECONDARY: list = [12, 13, 14, 16, 17, 18, 19, 21, 22, 23, 24, 26]
    ALL: list = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]
    HEADER: str = "Channel"

    def __init__(self, channel: int = None) -> None:
        self.__channel = channel

    def __str__(self) -> str:
        return f"{self.__channel}" if self.__channel is not None else "None"

    def __bool__(self) -> bool:
        return self.__channel is not None

    def __eq__(self, other) -> bool:
        if other is None:
            if self.__channel is None:
                return True
            else:
                return False
        if isinstance(other, Channel):
            return self.__channel == other.__channel
        if isinstance(other, int):
            return self.__channel == other
        raise NotImplemented

    def __ne__(self, other) -> bool:
        return not (self == other)

    def get(self) -> int:
        return self.__channel

    def set(self, channel: int = None) -> None:
        self.__channel = channel

    @staticmethod
    def is_usable(channel: int) -> bool:
        if channel is None:
            return False
        return channel in Channel.ALL

    @staticmethod
    def get_usable() -> Channel:
        return Channel(random.choice(Channel.ALL))

    @staticmethod
    def is_primary(channel: int) -> bool:
        if channel is None:
            return False
        return channel in Channel.PRIMARY

    @staticmethod
    def get_usable_primary() -> Channel:
        return Channel(random.choice(Channel.PRIMARY))

    @staticmethod
    def is_secondary(channel: int) -> bool:
        if channel is None:
            return False
        return channel in Channel.SECONDARY

    @staticmethod
    def get_usable_secondary() -> Channel:
        return Channel(random.choice(Channel.SECONDARY))

    @staticmethod
    def from_str(channel: str, random_ok: bool = True) -> Channel:
        if not channel:
            raise ValueError("cannot be empty")
        channel = channel.lower()
        if channel == "<random>":
            if random_ok:
                return Channel.get_usable()
            else:
                raise ValueError("invalid")
        channel = int(channel, 10)
        if not Channel.is_usable(channel):
            raise ValueError("not usable")
        return Channel(channel)


class Key:
    """Bytes wrapper for ZigBee key."""

    HEADER: str = "Key"

    def __init__(self, key: bytes = None) -> None:
        self.__key = key

    def __str__(self) -> str:
        return "0x" + self.__key.hex() if self.__key is not None else "None"

    def __bool__(self) -> bool:
        return self.__key is not None

    def __eq__(self, other) -> bool:
        if other is None:
            if self.__key is None:
                return True
            else:
                return False
        if isinstance(other, Key):
            return self.__key == other.__key
        if isinstance(other, int):
            return self.__key == other
        raise NotImplemented

    def __ne__(self, other) -> bool:
        return not (self == other)

    def get(self) -> bytes:
        return self.__key

    def set(self, key: bytes = None) -> None:
        self.__key = key

    @staticmethod
    def get_usable() -> Key:
        return Key.from_str(secrets.token_hex(16))

    @staticmethod
    def from_str(key: str, khash: bytes = None, random_ok: bool = True) -> Key:
        if not key:
            raise ValueError("cannot be empty")
        key = key.lower()
        if key == "<random>":
            if random_ok:
                return Key.get_usable()
            else:
                raise ValueError("invalid")
        # We actually allow 0xFF::::EE:BB... but that is okay
        key = key.replace(":", "")
        if key.startswith("0x"):
            key = key[2:]
        if len(key) != 32:
            raise ValueError("must be 128-bit")
        if not set(key).issubset(string.hexdigits):
            raise ValueError("not a valid hexstring")
        key = bytes.fromhex(key)
        if khash is not None:
            hasher = hashlib.sha256()
            hasher.update(key)
            if hasher.digest() != khash:
                raise ValueError("SHA-256 fail")
        return Key(key)


class Network:
    """Wraper for ZigBee network attributes."""

    HEADER: str = "Network"

    def __init__(
        self,
        ext_pan_id: ExtPanID = None,
        pan_id: PanID = None,
        channel: Channel = None,
        devices: Dict[int, Union(NwkAddr, IEEEAddr)] = None,
        key: Key = None,
    ) -> None:
        self.ext_pan_id = ext_pan_id if ext_pan_id is not None else ExtPanID()
        self.pan_id = pan_id if pan_id is not None else PanID()
        self.channel = channel if channel is not None else Channel()
        self.devices = devices if devices is not None else {}
        self.key = key if key is not None else Key()

    def __devices_str_list(self, header: bool = True, nwk_addr: bool = True) -> list:
        if not self.devices:
            return []
        devices = []

        # we support saving devices per nwk_addr or per ieee_addr
        value = random.choice(list(self.devices.values()))
        if isinstance(value, IEEEAddr):
            if header:
                devices.append([NwkAddr.HEADER, IEEEAddr.HEADER])
            for nwk_addr, ieee_addr in self.devices.items():
                devices.append([str(NwkAddr(nwk_addr)), str(ieee_addr)])
        elif isinstance(value, NwkAddr):
            if header:
                devices.append([IEEEAddr.HEADER, NwkAddr.HEADER])
            for ieee_addr, nwk_addr in self.devices.items():
                devices.append([str(IEEEAddr(ieee_addr)), str(nwk_addr)])

        return devices

    def devices_table(self, header: bool = True, nwk_addr: bool = True) -> str:
        """Return self.devices and tabulate table string.

        :param header: Include table header, defaults to True
        :type header: bool, optional
        :param nwk_addr: Include short addresses, defaults to True
        :type nwk_addr: bool, optional
        :return: String with tabulate table.
        :rtype: str
        """
        if not self.devices:
            return ""
        return tabulate.tabulate(
            self.__devices_str_list(header, nwk_addr),
            headers="firstrow",
            tablefmt="grid",
        )

    def __str__(self) -> str:
        # prepend lines
        devices_table = ""
        for line in self.devices_table().splitlines(True):
            devices_table += "    " + line
        # final string
        return (
            f"{ExtPanID.HEADER: <8}: {self.ext_pan_id}\n"
            + f"{PanID.HEADER: <8}: {self.pan_id}\n"
            + f"{Channel.HEADER: <8}: {self.channel}\n"
            + termcolor.colored(f"{Key.HEADER: <8}: {self.key}\n", attrs=["bold"])
            + f"{'Devices': <8}: #{len(self.devices)}\n"
            + devices_table
        )
