from typing import Type, List
import logging
import termcolor
import time

import scapy.all as sp

import zigtoucher.config as config
import zigtoucher.mode.base as modebase
import zigtoucher.transceiver as transceiver
import zigtoucher.writer as writer
import zigtoucher.zigbee.entity as zb_e
import zigtoucher.zigbee.touchlink.entity as zbt_e


logger = logging.getLogger("zigtoucher.mode.keylog")


class KeyLog(modebase.Mode):
    """Mode for catching and deciphering Touchlink transactions."""

    def __init__(
        self,
        _transceiver: Type[transceiver._Transceiver],
        timeout: int,
        channels: List[int],
        results: bool,
        csv: str,
        follow: bool,
        nwkcreate: bool,
        target: zb_e.IEEEAddr,
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
        :param follow: Follow into sniff mode?
        :type follow: bool
        :param nwkcreate: Save sniffed transactions into NWK files?
        :type nwkcreate: bool
        """
        super().__init__(_transceiver, timeout, channels, results)
        self.__csv = csv
        self.__follow = follow
        self.__nwkcreate = nwkcreate
        self.__target = target
        self.__transactions = {channel: {} for channel in self._channels}
        self._next_channel()

    def __pkt_skippable(self, pkt: sp.Packet) -> bool:
        """Is this packet Touchlink and target?

        :param pkt: Packet to be checked.
        :type pkt: sp.Packet
        :return: True if not interesting packet, False otherwise.
        :rtype: bool
        """
        return (
            pkt is None
            or not pkt.haslayer(sp.ZigbeeZLLCommissioningCluster)
            or (
                not pkt.haslayer(sp.ZLLScanRequest)
                and self.__target
                and pkt.src_addr != self.__target
                and pkt.dest_addr != self.__target
            )
        )

    def __print_results(self) -> None:
        """Print detailed results by channel."""
        for ch_i, (channel, transactions) in enumerate(self.__transactions.items()):
            print(
                termcolor.colored(f"\n Channel {channel} ", attrs=["bold", "reverse"])
            )
            for t_i, transaction in enumerate(transactions.values()):
                print(
                    "\n    "
                    + termcolor.colored(f"Transaction {ch_i + t_i}", attrs=["bold"])
                )
                for line in str(transaction).splitlines():
                    print("        " + line)

    def __print_summary(self) -> None:
        """Save exports, count summary and print quick results."""
        keys = 0
        transactions = 0
        for channel in self.__transactions.values():
            transactions += len(channel)
            for transaction in channel.values():
                if (
                    transaction.status == zbt_e.Transaction.Status.SUCCESS
                    and transaction.network.key
                ):
                    keys += 1
                self._export.append(transaction.pkts)

        print(
            termcolor.colored("\n Caught", attrs=["reverse"])
            + termcolor.colored(
                f" {transactions} {'transaction' if transactions == 1 else 'transactions'}",
                attrs=["reverse", "bold"],
            )
            + termcolor.colored(" and found", attrs=["reverse"])
            + termcolor.colored(
                f" {keys} {'key' if keys == 1 else 'keys'}. \n",
                attrs=["reverse", "bold"],
            )
        )

    def _act(self) -> str:
        """Init CSV writer if needed, and handle tranasctions
        using zbt_e.Transaction.update().

        :return: Sniff mode if self.__follow=True and found successful transaction.
        :rtype: str
        """

        try:  # lazyload csv writer here
            if self.__csv:
                self.__writer = writer.CSV(self.__csv)
                self.__writer.write(
                    [
                        zb_e.Key.HEADER,
                        zb_e.Channel.HEADER,
                        zb_e.ExtPanID.HEADER,
                        zb_e.PanID.HEADER,
                    ]
                )
                logger.info(f"writing keys into {self.__writer.path}")
            else:
                self.__writer = writer.Dummy()
        except Exception as e:
            logger.error(f"csv: {e}")
            return ""

        cmd = ""
        self._set_timer()
        with modebase.SignalHandler() as kbd:
            while not self.timeout() and not kbd.interrupted:

                if self._timer():  # cycle channels every 5 seconds
                    self._set_timer()
                    self._next_channel()

                pkt = self._transceiver.recv()
                if pkt is None:
                    if isinstance(self._transceiver, transceiver.PCAP):
                        break  # sniff on pcap file magic
                    continue
                if self.__pkt_skippable(pkt):
                    continue  # fastpath

                transaction_id = pkt.inter_pan_transaction_id
                if transaction_id not in self.__transactions[self._channel]:
                    self._set_timer()  # give this transaction time to finish
                    self.__transactions[self._channel][
                        transaction_id
                    ] = zbt_e.Transaction(pkt, self.__writer, self.__nwkcreate)
                else:
                    if (
                        self.__transactions[self._channel][transaction_id].update(pkt)
                        and self.__transactions[self._channel][transaction_id].status
                        == zbt_e.Transaction.Status.SUCCESS
                        and self.__follow
                    ):
                        network = self.__transactions[self._channel][
                            transaction_id
                        ].network
                        logger.info(f"switching to sniff on channel {network.channel}")
                        cmd = f"sniff channels={network.channel} key={network.key}"
                        break

        self.__writer.close()

        if self._results:
            self.__print_results()
        self.__print_summary()

        return cmd
