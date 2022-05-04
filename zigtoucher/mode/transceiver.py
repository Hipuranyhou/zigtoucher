from typing import Type
import logging

import zigtoucher.mode.base as modebase
import zigtoucher.transceiver as transceiver


logger = logging.getLogger("zigtoucher.mode.transceiver")


class Transceiver(modebase.Mode):
    """Mode for changing transceiver physical settings."""

    def __init__(
        self,
        _transceiver: Type[transceiver._Transceiver],
        rxgain: float,
        txgain: float,
        samprate: int,
    ) -> None:
        """Constructor saving all options for this run mode.

        :param _transceiver: Transceiver to be used for comms.
        :type _transceiver: Type[transceiver._Transceiver]
        :param rxgain: RX gain of transceiver in dB.
        :type rxgain: float
        :param txgain: TX gain of transceiver in dB.
        :type txgain: float
        :param samprate: Sample rate in samples.
        :type samprate: int
        """
        super().__init__(_transceiver, 0, [11], False)
        self.__rxgain = rxgain
        self.__txgain = txgain
        self.__samprate = samprate

    def _act(self) -> str:
        """Set transceiver settings to given values.

        :return: Empty string.
        :rtype: str
        """

        if self.__rxgain:
            self._transceiver.set_rxgain(self.__rxgain)
        if self.__txgain:
            self._transceiver.set_txgain(self.__txgain)
        if self.__samprate:
            self._transceiver.set_samprate(self.__samprate)
