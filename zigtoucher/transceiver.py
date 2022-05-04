from __future__ import annotations
from typing import Type
import abc
import enum
import logging

import scapy.all as sp
import scapy.modules.gnuradio as sp_gr

import zigtoucher.config as config
import zigtoucher.log as log
import zigtoucher.writer as writer
import zigtoucher.zigbee.entity as zb_e


logger = logging.getLogger("zigtoucher.transceiver")


class Type(enum.Enum):
    SDR = enum.auto()
    PCAP = enum.auto()

    @staticmethod
    def from_str(_type: str) -> Type:
        if not _type:
            raise ValueError("cannot be empty")
        _type = _type.lower()
        if _type == "sdr":
            return Type.SDR
        elif _type == "pcap":
            return Type.PCAP
        else:
            raise ValueError("must be one of {sdr|pcap}")


class _Transceiver(abc.ABC):
    def __init__(
        self, ieee_addr: zb_e.IEEEAddr, wireshark: bool = False, pcap: str = None
    ) -> None:
        """Open wireshark window and PCAP writer.

        :param ieee_addr: Source address to be used.
        :type ieee_addr: zb_e.IEEEAddr
        :param wireshark: Should Wireshark window be opened, defaults to False
        :type wireshark: bool, optional
        :param pcap: Path to output PCAP file, defaults to None
        :type pcap: str, optional
        """
        self._wireshark = writer.Wireshark() if wireshark else writer.Dummy()
        self._pcap = writer.PCAP(pcap) if pcap else writer.Dummy()
        self.ieee_addr = ieee_addr
        self._last_pkt = sp.Packet()
        self._next_pkt = None

    def _close(self) -> None:
        """Clsoe Wireshark window and PCAP writer."""
        self._wireshark.close()
        self._pcap.close()

    @abc.abstractmethod
    def recv(self, timeout: float = 0.33) -> sp.Packet:
        ...

    @abc.abstractmethod
    def send(self, pkt: sp.Packet) -> None:
        ...

    @abc.abstractmethod
    def set_channel(self, channel: int = 11) -> None:
        ...

    @abc.abstractmethod
    def set_rxgain(self, gain: float = 0.0) -> None:
        ...

    @abc.abstractmethod
    def set_txgain(self, gain: float = 0.0) -> None:
        ...

    @abc.abstractmethod
    def set_samprate(self, samprate: int = 0.0) -> None:
        ...

    @abc.abstractmethod
    def close(self) -> None:
        ...


class SDR(_Transceiver):
    RXGAIN_MAX: float = 76.0
    TXGAIN_MAX: float = 89.8
    SAMPRATE_MAX: int = 100000000

    def __init__(
        self,
        ieee_addr: zb_e.IEEEAddr,
        flowgraph: str,
        timeout: int,
        wireshark: bool = False,
        pcap: str = None,
    ) -> None:
        """Open all windows and files and start GNU Radio flowgraph and set
        physical settings from default configuration.

        :param ieee_addr: Source address to be used.
        :type ieee_addr: zb_e.IEEEAddr
        :param flowgraph: Flowgraph name to be used.
        :type flowgraph: str
        :param timeout: Timeout for SDR wait.
        :type timeout: int
        :param wireshark: Should wireshark window be opened, defaults to False
        :type wireshark: bool, optional
        :param pcap: Path to output PCAP file, defaults to None
        :type pcap: str, optional
        """
        super().__init__(ieee_addr, wireshark, pcap)
        if isinstance(self._pcap, writer.PCAP):
            logger.info(f"writing packets into {self._pcap.path}")

        # init and wait for gnuradio
        sp.load_module("gnuradio")
        sp_gr.gnuradio_start_flowgraph(flowgraph, timeout=timeout)

        # set default physical configuration
        gain = config.get("transceiver.rxgain")
        if gain:
            self.set_rxgain(gain)
        gain = config.get("transceiver.txgain")
        if gain:
            self.set_txgain(gain)
        samprate = config.get("transceiver.samprate")
        if samprate:
            self.set_samprate(samprate)

    def recv(self, timeout: float = 0.35) -> sp.Packet:
        """Recv 2 packets using sp.srradio().

        We receive 2 because we often receive the one we just send and need to
        filter it out. If the first received is not the last one send by us, we save the
        other in queue and return it on next call.

        :param timeout: Timeout for Scapy, defaults to 0.35
        :type timeout: float, optional
        :return: Received packet.
        :rtype: sp.Packet
        """

        if self._next_pkt:
            pkts = [self._next_pkt]
            self._next_pkt = None
        else:
            pkts = sniffradio(count=2, timeout=timeout)

        # do not receive pkt we just sent
        if len(pkts) == 0:
            return None  # fastpath
        pkt = pkts[0]
        if hasattr(pkt, "fcs"):
            pkt.fcs = None
        if pkt == self._last_pkt:
            if len(pkts) == 1:
                return None
            elif len(pkts) == 2:
                pkt = pkts[1]
        elif len(pkts) == 2:
            self._next_pkt = pkts[1]

        self._wireshark.write(pkt)
        self._pcap.write(pkt)
        return pkt

    def send(self, pkt: sp.Packet) -> None:
        """Send given packet using sp.send() and write to all windows and files.

        Save this packet as last sent without FCS.

        :param pkt: Packet to be send.
        :type pkt: sp.Packet
        """
        if hasattr(pkt, "fcs"):
            pkt.fcs = None
        self._last_pkt = pkt
        self._wireshark.write(pkt)
        self._pcap.write(pkt)
        sp.send(pkt)

    def set_channel(self, channel: int = 11) -> None:
        """Set GNU Radio channel variable.

        :param channel: ZigBee channel, defaults to 11
        :type channel: int, optional
        """
        if channel < 11 or channel > 26:
            raise ValueError("channel must be >= 11 and <= 26")
        sp_gr.gnuradio_set_vars(channel=channel)

    def set_rxgain(self, gain: float = 30.0) -> None:
        """Set GNU Radio rxgain variable.

        :param gain: RX gain in dB, defaults to 30.0
        :type gain: float, optional
        """
        if gain < 0.0:
            gain = 0.0
            logger.info("setting to min 0.0")
        if gain > SDR.RXGAIN_MAX:
            gain = SDR.RXGAIN_MAX
            logger.info(f"setting rxgain to max {SDR.RXGAIN_MAX}")
        sp_gr.gnuradio_set_vars(rxgain=gain)

    def set_txgain(self, gain: float = 89.0) -> None:
        """Set GNU Radio txgain variable.

        :param gain: TX gain in dB, defaults to 89.0
        :type gain: float, optional
        """
        if gain < 0.0:
            gain = 0.0
            logger.info("setting to min 0.0")
        if gain > SDR.TXGAIN_MAX:
            gain = SDR.TXGAIN_MAX
            logger.info(f"setting txgain to max {SDR.TXGAIN_MAX}")
        sp_gr.gnuradio_set_vars(txgain=gain)

    def set_samprate(self, samprate: int = 4000000) -> None:
        """Set GNU Radio samprate variable.

        :param samprate: Sample rate in samples, defaults to 4000000
        :type samprate: int, optional
        """
        if samprate < 0.0:
            samprate = 0.0
            logger.info("setting to min 0.0")
        sp_gr.gnuradio_set_vars(samprate=samprate)

    def close(self) -> None:
        """Close all windows, files and stop GNU Radio flowgraph."""
        super()._close()
        sp_gr.gnuradio_stop_flowgraph()


class PCAP(_Transceiver):
    def __init__(
        self, ieee_addr: zb_e.IEEEAddr, wireshark: bool = False, pcap: str = None
    ) -> None:
        """Prepare sp.PcapReader.

        :param ieee_addr: Ignored
        :type ieee_addr: zb_e.IEEEAddr
        :param wireshark: Should wireshark window be opened, defaults to False
        :type wireshark: bool, optional
        :param pcap: Path to PCAP file to be read, defaults to None
        :type pcap: str, optional
        """
        super().__init__(ieee_addr, wireshark, None)
        self.reader = sp.PcapReader(pcap)

    def recv(self, timeout: float = 0.33) -> sp.Packet:
        """Read one packet from loaded PCAP file or return None on EOF.

        :param timeout: Ignored, defaults to 0.33
        :type timeout: float, optional
        :return: Packet or None.
        :rtype: sp.Packet
        """
        try:
            pkt = self.reader.recv()
        except EOFError:
            logger.info("reached pcap EOF")
            return None
        self._wireshark.write(pkt)
        return pkt

    def send(self, pkt: sp.Packet) -> None:
        logger.debug("PCAP() pseudotransceiver does not implement send()")

    def set_channel(self, channel: int = 11) -> None:
        logger.debug("PCAP() pseudotransceiver does not implement set_channel()")

    def set_rxgain(self, gain: float = 0.0) -> None:
        logger.debug("PCAP() pseudotransceiver does not implement set_rxgain()")

    def set_txgain(self, gain: float = 0.0) -> None:
        logger.debug("PCAP() pseudotransceiver does not implement set_txgain()")

    def set_samprate(self, samprate: int = 4000000) -> None:
        logger.debug("PCAP() pseudotransceiver does not implement set_samprate()")

    def close(self) -> None:
        super()._close()
