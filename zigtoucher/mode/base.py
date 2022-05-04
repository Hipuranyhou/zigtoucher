from typing import Type, List
import abc
import logging
import signal
import termcolor
import time

import zigtoucher.config as config
import zigtoucher.transceiver as transceiver
import zigtoucher.writer as writer
import zigtoucher.zigbee.entity as zb_e


logger = logging.getLogger("zigtoucher.mode.base")


class SignalHandler(object):
    """Context manager for given signals
    from https://gist.github.com/nonZero/2907502
    """

    def __init__(self, signals=[signal.SIGINT]) -> None:
        """Constructor saving signal to be ignored.

        :param signals: Signals to be ignored, defaults to [signal.SIGINT].
        :type signals: list, optional
        """
        self.interrupted = False
        self.__signals = signals
        self.__released = False
        self.__original_handlers = {}

    def __release(self) -> bool:
        """Revert back original signal handlers.

        :return: True released, False already released.
        :rtype: bool
        """
        if self.__released:
            return False
        for sig in self.__signals:
            signal.signal(sig, self.__original_handlers[sig])
        self.__released = True
        return True

    def __handler(self, signum, frame) -> None:
        self.interrupted = True

    def __enter__(self):
        self.interrupted = False
        self.__released = False
        for sig in self.__signals:
            self.__original_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, self.__handler)
        return self

    def __exit__(self, type, value, tb) -> None:
        self.__release()


class Mode(abc.ABC):
    """Abstract class for implementing run modes."""

    def __init__(
        self,
        _transceiver: Type[transceiver._Transceiver],
        timeout: int,
        channels: List[int],
        results: bool,
        address: zb_e.IEEEAddr = None,
    ) -> None:
        """Constructor saving general options for run mode.

        :param _transceiver: Transceiver to be used for comms.
        :type _transceiver: Type[transceiver._Transceiver]
        :param timeout: Timeout for automatic mode exit.
        :type timeout: int
        :param channels: Channels to be cycled while running.
        :type channels: List[int]
        :param results: Show detailed results.
        :type results: bool
        :param address: Address to be used for sending packets, defaults to None.
        :type address: zb_e.IEEEAddr, optional
        """
        self._transceiver = _transceiver
        self._timeout = timeout
        if isinstance(_transceiver, transceiver.PCAP):
            channels = ["PCAP"]
        self._channels = channels
        self._results = results
        if address and self._transceiver.ieee_addr != address:
            self._transceiver.ieee_addr = address
        self._stop_time = None
        self._export = []
        self._channels_i = -1

    def start(self) -> str:
        """Setup timeout flag for run mode and call its self._act() method.

        :return: Command line to be used as following mode by cmd.Cmd.
        :rtype: str
        """
        self._stop_time = time.time() + self._timeout if self._timeout > 0 else None
        self._export = []
        self._channels_i = -1
        cmd = self._act()
        self._stop_time = None
        return cmd

    def timeout(self) -> bool:
        """Check if time.time() reached timeout.

        :return: True if reached, False means continue running.
        :rtype: bool
        """
        return self._stop_time is not None and time.time() >= self._stop_time

    def export(self, idx: int, pcap: str = None) -> None:
        """Export packets from self._results[idx] into given PCAP file.

        :param idx: Index to self._results to export.
        :type idx: int
        :param pcap: Path to output PCAP file, defaults to <random>.
        :type pcap: str, optional
        """
        if not self._export:
            logger.info("nothing to export")
            return
        if idx is None:
            logger.error("idx: missing")
            return
        if idx >= len(self._export):
            logger.error("idx: out of bounds")
            return
        try:
            with writer.PCAP(pcap) as _writer:
                for pkt in self._export[idx]:
                    _writer.write(pkt)
                logger.info(
                    f"wrote #{len(self._export[idx])}"
                    f" {'packet' if len(self._export[idx]) == 1 else 'packets'}"
                    f" into {_writer.path}"
                )
        except Exception as e:
            logger.error(f"{e}")
            return

    def confirm(self, msg: str) -> bool:
        """Ask user for confirmation with given message.

        :param msg: Question do display.
        :type msg: str
        :return: True for confirm, False for no confirm or EOF.
        :rtype: bool
        """
        result = None
        while result is None:
            try:
                val = input(
                    termcolor.colored(f"\n{msg} [boolean]:", attrs=["bold", "reverse"])
                    + " "
                )
                result = config.to_bool(val)
            except (TypeError, ValueError) as e:
                logger.error(f"{e}")
                result = False
            except EOFError:
                result = False
        print("")
        return result

    def _next_channel(self):
        """Move self._channels_i by 1 (or rollover to 0) and
        set self._channel from self._channles in self._transceiver.
        """
        self._channels_i += 1
        if self._channels_i == len(self._channels):
            self._channels_i = 0
        self._channel = self._channels[self._channels_i]
        self._transceiver.set_channel(self._channel)

    def _set_timer(self, timeout: float = 5) -> None:
        """Set timer flag.

        :param timeout: Timer timeout end in seconds, defaults to 5
        :type timeout: float, optional
        """
        self._timer_end = time.time() + timeout

    def _timer(self) -> bool:
        """Check if timer flag expired.

        :return: True if expired, False otherwise.
        :rtype: bool
        """
        return time.time() >= self._timer_end

    @abc.abstractmethod
    def _act(self) -> str:
        ...
