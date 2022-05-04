from typing import Type, List
import logging
import termcolor
import time

import scapy.all as sp

import zigtoucher.config as config
import zigtoucher.mode.base as modebase
import zigtoucher.transceiver as transceiver
import zigtoucher.writer as writer
import zigtoucher.zigbee.crypto as zb_c
import zigtoucher.zigbee.entity as zb_e


logger = logging.getLogger("zigtoucher.mode.sniff")


class Sniff(modebase.Mode):
    """Mode for sniffing and deciphering general ZigBee packets."""

    def __init__(
        self,
        _transceiver: Type[transceiver._Transceiver],
        timeout: int,
        channels: List[int],
        results: bool,
        pcap: str,
        key: zb_e.Key,
        show: bool,
    ) -> None:
        """Constructor saving all options for this run mode.

        :param _transceiver: Transceiver to be used for comms.
        :type _transceiver: Type[transceiver._Transceiver]
        :param timeout: Timeout for automatic mode exit.
        :type timeout: int
        :param channels: Channels to be cycled while running.
        :type channels: List[int]
        :param results: Show detailed results.
        :type results: bool
        :param pcap: Path to output PCAP file.
        :type pcap: str
        :param key: Key used for deciphering ZigBee packets.
        :type key: zb_e.Key
        :param show: Show sniffed packets usign Scapy show().
        :type show: bool
        """
        super().__init__(_transceiver, timeout, channels, results)
        self.__pcap = pcap
        self.__key = key
        self.__writer = None
        self.__show = show
        self.__cnts = {channel: 0 for channel in self._channels}

    def __print_results(self) -> None:
        """Print detailed results by channel."""
        for channel, cnts in self.__cnts.items():
            print(
                termcolor.colored(f"\n Channel {channel} \n", attrs=["bold", "reverse"])
            )
            print(f"    Catched {cnts} {'packet' if cnts == 1 else 'packets'}.")

    def __print_summary(self) -> None:
        """Print quick results."""
        cnt = 0
        for cnts in self.__cnts.values():
            cnt += cnts
        print(
            termcolor.colored("\n Catched", attrs=["reverse"])
            + termcolor.colored(
                f" {cnt} {'packet' if cnt == 1 else 'packets'}. \n",
                attrs=["reverse", "bold"],
            )
        )

    def _act(self) -> str:
        """Sniff ZigBee packets and save their deciphered version using given key.

        :return: Empty string.
        :rtype: str
        """

        try:  # lazyload PCAP writer here
            self.__writer = writer.PCAP(self.__pcap)
            logger.info(f"writing packets into {self.__writer.path}")
        except Exception as e:
            logger.error(f"pcap: {e}")
            return ""

        if not self.__key:
            logger.info("decryption disabled")

        with modebase.SignalHandler() as kbd:
            while not self.timeout() and not kbd.interrupted:

                self._next_channel()  # cycle channels every round

                pkt = self._transceiver.recv()
                if pkt is None:
                    if isinstance(self._transceiver, transceiver.PCAP):
                        break  # sniff on pcap file magic
                    continue  # fastpath

                self.__cnts[self._channel] += 1
                if pkt.haslayer(sp.ZigbeeSecurityHeader) and self.__key:
                    pkt = zb_c.decrypt(pkt, self.__key.get())
                try:
                    self.__writer.write(pkt)
                except Exception as e:
                    logger.error(f"pcap: {e}")
                if self.__show:
                    pkt.show()

        self.__writer.close()

        if self._results:
            self.__print_results()
        self.__print_summary()

        return ""
