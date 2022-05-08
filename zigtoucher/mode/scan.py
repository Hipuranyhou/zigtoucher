from typing import Type, List, Set
import enum
import logging
import tabulate
import termcolor
import time

import scapy.all as sp

import zigtoucher.config as config
import zigtoucher.mode.base as modebase
import zigtoucher.transceiver as transceiver
import zigtoucher.writer as writer
import zigtoucher.zigbee.entity as zb_e
import zigtoucher.zigbee.touchlink.builder as zbt_b


logger = logging.getLogger("zigtoucher.mode.scan")


class Scan(modebase.Mode):
    """Mode for scaning surroundings for Touchlink capable devices."""

    # FSM states
    class _State(enum.Enum):
        """Scan mode FSM states."""

        SEND_SCAN = enum.auto()
        RECV_RESP = enum.auto()

    def __init__(
        self,
        _transceiver: Type[transceiver._Transceiver],
        timeout: int,
        channels: List[int],
        results: bool,
        csv: str,
        address: zb_e.IEEEAddr,
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
        :param csv: Path to output CSV file.
        :type csv: str
        :param address: Source address used by transceiver.
        :type address: zb_e.IEEEAddr
        """
        super().__init__(_transceiver, timeout, channels, results, address)
        self.__csv = csv
        self.__targets = {}
        for channel in self._channels:
            self.__targets[channel] = set()
        self.__reset()

    def __reset(self) -> None:
        """Reset FSM state and packet builder attributes to defaults. Move channel."""
        self.__scan_cnt = 0
        self.__dest_ieee_addr = zb_e.IEEEAddr()
        self.__builder = zbt_b.Builder(self._transceiver.ieee_addr)
        self.__state = self._State.SEND_SCAN
        self._next_channel()

    def __pkt_skippable(self, pkt: sp.Packet) -> bool:
        """Is this packet Touchlink?

        :param pkt: Packet to be checked.
        :type pkt: sp.Packet
        :return: True if not interesting packet, False otherwise.
        :rtype: bool
        """
        return (
            pkt is None
            or not pkt.haslayer(sp.ZLLScanResponse)
            or pkt.inter_pan_transaction_id != self.__builder.ipan_transaction_id
        )

    def __print_results(self) -> None:
        """Print detailed results by channel."""
        for channel, targets in self.__targets.items():
            print(
                termcolor.colored(f"\n Channel {channel} \n", attrs=["bold", "reverse"])
            )
            table = [[zb_e.IEEEAddr.HEADER]]
            for target in targets:
                table.append([str(zb_e.IEEEAddr(target))])
            for line in tabulate.tabulate(
                table, headers="firstrow", tablefmt="grid"
            ).splitlines():
                print("    " + line)

    def __print_summary(self) -> None:
        """Print quick results."""
        cnt = 0
        for targets in self.__targets.values():
            cnt += len(targets)
        print(
            termcolor.colored("\n Found", attrs=["reverse"])
            + termcolor.colored(
                f" {cnt} {'target' if cnt == 1 else 'targets'} ",
                attrs=["reverse", "bold"],
            )
            + termcolor.colored("\n", attrs=["reverse"])
        )

    def _act(self) -> str:
        """Simply scan for Touchlink devices by sending scan requests.

        :return: Empty string.
        :rtype: str
        """

        try:  # lazyload csv writer here
            if self.__csv:
                self.__writer = writer.CSV(self.__csv)
                self.__writer.write([zb_e.IEEEAddr.HEADER, zb_e.Channel.HEADER])
                logger.info(f"writing targets into {self.__writer.path}")
            else:
                self.__writer = writer.Dummy()
        except Exception as e:
            logger.error(f"failed to init csv writer: {e}")
            return ""

        with modebase.SignalHandler() as kbd:
            while not self.timeout() and not kbd.interrupted:

                # we could use sp.srradio() function but I like the separation like this
                # using the FSM and it is quick enough

                if self.__state == self._State.SEND_SCAN:
                    if self.__scan_cnt == 5:  # cycle channels after 5 scans
                        self.__reset()
                        continue
                    if self.__scan_cnt == 0:
                        pkt = self.__builder.scan_request()
                    else:
                        pkt = self.__builder.rebuild_mac_seqnum()
                    self.__scan_cnt += 1
                    self._transceiver.send(pkt)
                    self.__state = self._State.RECV_RESP

                elif self.__state == self._State.RECV_RESP:
                    pkt = self._transceiver.recv()
                    if self.__pkt_skippable(pkt):
                        self.__state = self._State.SEND_SCAN
                        continue  # fastpath
                    self.__dest_ieee_addr.set(pkt.src_addr)
                    if self.__dest_ieee_addr.get() in self.__targets[self._channel]:
                        self.__reset()
                        continue  # skip already found
                    logger.info(f"{self.__dest_ieee_addr} on channel {self._channel}")
                    try:
                        self.__writer.write([self.__dest_ieee_addr, self._channel])
                    except Exception as e:
                        logger.error(f"csv: {e}")
                    self.__targets[self._channel].add(self.__dest_ieee_addr.get())
                    self.__reset()

        self.__writer.close()

        if self._results:
            self.__print_results()
        self.__print_summary()

        return ""
