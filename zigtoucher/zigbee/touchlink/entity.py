from __future__ import annotations
import enum
import logging
import random

import scapy.all as sp

import zigtoucher.config as config
import zigtoucher.nwkcontrol as nwkcontrol
import zigtoucher.writer as writer
import zigtoucher.zigbee.entity as zb_e
import zigtoucher.zigbee.touchlink.crypto as zbt_c


logger = logging.getLogger("zigtoucher.zigbee.touchlink.entity")


class IPANTransactionID:
    """Int wrapper for Touchlink Transaction ID."""

    BITS: int = 32
    MIN: int = 0x00000001
    MAX: int = 0xFFFFFFFF
    HEADER: str = "IPANTransactionID"

    def __init__(self, ipan_transaction_id: int = None) -> None:
        self.__ipan_transaction_id = ipan_transaction_id

    def __str__(self) -> str:
        return (
            f"0x{self.__ipan_transaction_id:08x}"
            if self.__ipan_transaction_id is not None
            else "None"
        )

    def __bool__(self) -> bool:
        return self.__ipan_transaction_id is not None

    def __eq__(self, other) -> bool:
        if other is None:
            if self.__ipan_transaction_id is None:
                return True
            else:
                return False
        if isinstance(other, IPANTransactionID):
            return self.__ipan_transaction_id == other.__ipan_transaction_id
        if isinstance(other, int):
            return self.__ipan_transaction_id == other
        raise NotImplemented

    def __ne__(self, other) -> bool:
        return not (self == other)

    def get(self) -> int:
        return self.__ipan_transaction_id

    def set(self, ipan_transaction_id: int = None) -> None:
        self.__ipan_transaction_id = ipan_transaction_id

    @staticmethod
    def __is_usable(ipan_transaction_id: int) -> bool:
        return ipan_transaction_id >= IPANTransactionID.MIN

    @staticmethod
    def is_usable(ipan_transaction_id: IPANTransactionID) -> bool:
        return IPANTransactionID.__is_usable(ipan_transaction_id.get())

    @staticmethod
    def get_usable() -> IPANTransactionID:
        ipan_transaction_id = random.getrandbits(IPANTransactionID.BITS)
        while not IPANTransactionID.__is_usable(ipan_transaction_id):
            ipan_transaction_id = random.getrandbits(IPANTransactionID.BITS)
        return IPANTransactionID(ipan_transaction_id)


class Transaction:
    HEADER: str = "Transaction"

    class Status(enum.Enum):
        SUCCESS = enum.auto()
        FAILURE = enum.auto()
        UNKNOWN = enum.auto()

        def __str__(self) -> str:
            return f"{str(self._name_).replace('_', ' ').capitalize()}"

    class Type(enum.Enum):
        SCAN = enum.auto()
        IDENTIFY = enum.auto()
        RESET = enum.auto()
        KEY_TRANSPORT = enum.auto()
        UNKNOWN = enum.auto()

        def __str__(self) -> str:
            return f"{str(self._name_).replace('_', ' ').capitalize()}"

    def __init__(
        self, pkt: Packet, writer: writer.CSV = None, nwkcreate: bool = None
    ) -> None:
        if not pkt.haslayer(sp.ZigbeeZLLCommissioningCluster):
            raise ValueError("does not have Touchlink layer")
        self.ipan_transaction_id = IPANTransactionID(pkt.inter_pan_transaction_id)
        self.response_id = None
        self.network = zb_e.Network()
        self.pkts = []
        self.__writer = writer if writer is not None else writer.Dummy()
        self.__nwkcreate = nwkcreate if nwkcreate is not None else False
        self.update(pkt)

    def __update_status(self, pkt: Packet) -> None:
        if not hasattr(pkt, "status"):
            self.status = Transaction.Status.UNKNOWN
        elif pkt.status == 0:
            self.status = Transaction.Status.SUCCESS
        elif pkt.status == 1:
            self.status = Transaction.Status.FAILURE
        else:
            self.status = Transaction.Status.UNKNOWN

    def __update_type(self, pkt: Packet) -> None:
        if pkt.haslayer(sp.ZLLScanRequest):
            self.type = Transaction.Type.SCAN
        elif pkt.haslayer(sp.ZLLIdentifyRequest):
            self.type = Transaction.Type.IDENTIFY
        elif pkt.haslayer(sp.ZLLResetToFactoryNewRequest):
            self.type = Transaction.Type.RESET
        elif (
            pkt.haslayer(sp.ZLLNetworkStartRequest)
            or pkt.haslayer(sp.ZLLNetworkStartResponse)
            or pkt.haslayer(sp.ZLLNetworkJoinRouterRequest)
            or pkt.haslayer(sp.ZLLNetworkJoinRouterResponse)
            or pkt.haslayer(sp.ZLLNetworkJoinEndDeviceRequest)
            or pkt.haslayer(sp.ZLLNetworkJoinEndDeviceResponse)
        ):
            self.type = Transaction.Type.KEY_TRANSPORT
        else:
            self.type = Transaction.Type.UNKNOWN

    def __update_devices(self, ieee_addr: int, nwk_addr: int = None) -> None:
        """Save or update given short addres in self.network at given ieee_addr.

        :param ieee_addr: IEEE address key.
        :type ieee_addr: int
        :param nwk_addr: NwkAddr value, defaults to None
        :type nwk_addr: int, optional
        """
        if ieee_addr not in self.network.devices:
            self.network.devices[ieee_addr] = zb_e.NwkAddr(nwk_addr)
        elif nwk_addr is not None:
            self.network.devices[ieee_addr].set(nwk_addr)

    def __log_key(self):
        if not self.network.key:
            return
        logger.info(
            f"{self.network.key} for"
            f" PAN {self.network.pan_id}"
            f" (CH {self.network.channel})"
        )

    def __save(self):
        """Write key to CSV and NWK files if found and successful."""
        if not self.network.key or self.status != Transaction.Status.SUCCESS:
            return  # do not write unverified keys
        try:
            self.__writer.write(
                [
                    self.network.key,
                    self.network.channel,
                    self.network.ext_pan_id,
                    self.network.pan_id,
                ]
            )
        except Exception as e:
            logger.error(f"csv: {e}")
        if self.__nwkcreate:
            try:
                nwkcontrol.NwkControl.save_network(self.network)
            except Exception as e:
                logger.error(f"nwkcontrol: {e}")

    def __decrypt_nwk_key(self, pkt: Packet) -> bytes:
        if self.response_id is None:
            logger.error(
                f"{self.ipan_transaction_id} cannot decrypt network"
                " key without response_id"
            )
            return None

        development = False
        if pkt.key_index == 0:
            key = zb_e.Key(
                zbt_c.get_development_key(
                    self.ipan_transaction_id.get(), self.response_id
                )
            )
            development = True
        elif pkt.key_index == 4:
            key = config.get("keys.touchlink.master")
        elif pkt.key_index == 15:
            key = config.get("keys.touchlink.certification")
        else:
            logger.error(f"{self.ipan_transaction_id} unknown key type {pkt.key_index}")
            return None
        if not key:
            logger.error(
                f"{self.ipan_transaction_id} cannot decrypt network key without key"
            )
            return None

        return zbt_c.decrypt_nwk_key(
            self.ipan_transaction_id.get(),
            self.response_id,
            key.get(),
            pkt.encrypted_network_key.to_bytes(16, "big"),
            development,
        )

    def update(self, pkt: Packet) -> bool:
        """Diagnose given Touchlink packet based on its layer and saving its values.

        :param pkt: Packet to be diagnosed.
        :type pkt: Packet
        :return: Did the transaction ended successfuly?
        :rtype: bool
        """

        if pkt.inter_pan_transaction_id != self.ipan_transaction_id.get():
            return False

        self.__update_devices(pkt.src_addr)
        self.__update_status(pkt)
        self.__update_type(pkt)
        self.pkts.append(pkt)

        if pkt.haslayer(sp.ZLLScanResponse):
            layer = pkt[sp.ZLLScanResponse]
            self.response_id = layer.response_id
            return False

        if pkt.haslayer(sp.ZLLIdentifyRequest):
            return False  # can end with this but it is highly improbable

        if pkt.haslayer(sp.ZLLResetToFactoryNewRequest):
            return True

        if pkt.haslayer(sp.ZLLNetworkStartRequest):
            # lots of optionals in NetworkStartRequest
            layer = pkt[sp.ZLLNetworkStartRequest]
            if layer.pan_id_ext != 0:
                self.network.ext_pan_id.set(layer.pan_id_ext)
            if layer.channel != 0:
                self.network.channel.set(layer.channel)
            if layer.pan_id != 0:
                self.network.pan_id.set(layer.pan_id)
            self.__update_devices(pkt.dest_addr, layer.network_address)
            self.__update_devices(
                int.from_bytes(
                    layer.initiator_ieee_address.to_bytes(8, "little"), "big"
                ),
                layer.initiator_network_address,
            )
            self.network.key.set(self.__decrypt_nwk_key(pkt))
            return False

        if pkt.haslayer(sp.ZLLNetworkStartResponse):
            layer = pkt[sp.ZLLNetworkStartResponse]
            self.network.ext_pan_id.set(layer.pan_id_ext)
            self.network.channel.set(layer.channel)
            self.network.pan_id.set(layer.pan_id)
            self.__log_key()
            self.__save()
            return True

        if pkt.haslayer(sp.ZLLNetworkJoinRouterRequest):
            layer = pkt[sp.ZLLNetworkJoinRouterRequest]
            self.network.ext_pan_id.set(layer.pan_id_ext)
            self.network.channel.set(layer.channel)
            self.network.pan_id.set(layer.pan_id)
            self.__update_devices(pkt.src_addr, zb_e.NwkAddr.INITIATOR)
            self.__update_devices(pkt.dest_addr, layer.network_address)
            self.network.key.set(self.__decrypt_nwk_key(pkt))
            self.__log_key()
            return False

        if pkt.haslayer(sp.ZLLNetworkJoinRouterResponse):
            self.__save()
            return True

        if pkt.haslayer(sp.ZLLNetworkJoinEndDeviceRequest):
            layer = pkt[sp.ZLLNetworkJoinEndDeviceRequest]
            self.network.ext_pan_id.set(layer.pan_id_ext)
            self.network.channel.set(layer.channel)
            self.network.pan_id.set(layer.pan_id)
            self.__update_devices(pkt.src_addr, zb_e.NwkAddr.INITIATOR)
            self.__update_devices(pkt.dest_addr, layer.network_address)
            self.network.key.set(self.__decrypt_nwk_key(pkt))
            self.__log_key()
            return False

        if pkt.haslayer(sp.ZLLNetworkJoinEndDeviceResponse):
            self.__save()
            return True

        return False

    def __str__(self) -> str:

        # formatting
        response_id = (
            f"0x{self.response_id:08x}" if self.response_id is not None else "None"
        )

        # show network only if makes sense
        devices = ""
        network = f"{zb_e.Network.HEADER: <17}:"
        if self.type == Transaction.Type.KEY_TRANSPORT:
            network += "\n"
            for line in str(self.network).splitlines(True):
                network += "    " + line
        else:
            network += " None\n"
            devices = f"{'Devices': <17}: #{len(self.network.devices)}\n"
            for line in self.network.devices_table(nwk_addr=False).splitlines(True):
                devices += "    " + line

        # show status only if known
        status = (
            f"{'Status': <17}: {self.status}\n"
            if self.status != Transaction.Status.UNKNOWN
            else ""
        )

        return (
            f"{IPANTransactionID.HEADER: <17}: {self.ipan_transaction_id}\n"
            + f"{'ResponseID': <17}: {response_id}\n"
            + f"{'Type': <17}: {self.type}\n"
            + status
            + f"{'Packets': <17}: #{len(self.pkts)}\n"
            + network
            + devices
        )
