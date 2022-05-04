from xdg.BaseDirectory import xdg_data_home
from typing import Iterable, Any
import abc
import csv
import datetime
import logging
import os
import subprocess
import tempfile

import scapy.all as sp


logger = logging.getLogger("zigtoucher.writer")


def ignore_sigint():
    os.setpgrp()


class Writer(abc.ABC):
    PREFIX: str = f"{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}_"
    USER_DATA: str = os.path.join(xdg_data_home, "zigtoucher")
    RANDOM: str = "<random>"

    def __init__(self, path: str = None) -> None:
        """Create XDG Data Home if needed.

        :param path: Path to written file, defaults to None
        :type path: str, optional
        """
        self.path = path if path else ""
        self._file = None
        self._writer = None
        Writer.create_user_data()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    @staticmethod
    def create_user_data() -> None:
        """Create XDG Data Home if needed."""
        if not os.path.exists(Writer.USER_DATA):
            os.makedirs(Writer.USER_DATA)

    @abc.abstractmethod
    def write(self, data: Any) -> None:
        ...

    @abc.abstractmethod
    def close(self) -> None:
        ...


class Dummy(Writer):
    def write(self, data: Any) -> None:
        """Do nothing.

        :param data: Anything.
        :type data: Any
        """
        return

    def close(self) -> None:
        """Do nothing."""
        return


class PCAP(Writer):
    def __init__(self, path: str) -> None:
        """Prepare sp.RawPcapWriter instance with tempfile.NamedTemporaryFile if needed.

        :param path: Path to PCAP file.
        :type path: str
        """
        super().__init__(path)
        self._file = (
            tempfile.NamedTemporaryFile(
                "wb",
                prefix=self.PREFIX,
                suffix=".pcap",
                delete=False,
                dir=self.USER_DATA,
            )
            if not path or path == self.RANDOM
            else open(path, "wb")
        )
        self._writer = sp.RawPcapWriter(
            self._file, linktype=sp.DLT_IEEE802_15_4_WITHFCS
        )
        self.path = self._file.name

    def write(self, pkt: sp.Packet) -> None:
        """Write given packet to the file.

        :param pkt: Packet to be written.
        :type pkt: sp.Packet
        """
        self._writer.write(pkt)

    def close(self) -> None:
        """Flush sp.RawPcapWriter and close the PCAP file."""
        self._writer.flush()
        self._file.close()


class CSV(Writer):
    def __init__(self, path: str) -> None:
        """Prepare csv.writer instance with tempfile.NamedTemporaryFile if needed.

        :param path: Path to CSV file.
        :type path: str
        """
        super().__init__(path)
        self._file = (
            tempfile.NamedTemporaryFile(
                "w",
                prefix=self.PREFIX,
                suffix=".csv",
                delete=False,
                dir=self.USER_DATA,
                newline="",
            )
            if not path or path == self.RANDOM
            else open(path, "w", newline="")
        )
        self._writer = csv.writer(self._file)
        self.path = self._file.name

    def write(self, row: Iterable[Any]) -> None:
        """Write CSV row.

        :param row: CSV row to be written.
        :type row: Iterable[Any]
        """
        self._writer.writerow(row)

    def close(self) -> None:
        """Close CSV file."""
        self._file.close()


class Wireshark(Writer):
    """Writer for live capture in Wireshark window."""

    def __init__(self, path: str = None) -> None:
        """Open Wireshark window with subprocess.Popen and prepare sp.RawPcapWriter.

        :param path: Ignored.
        :type path: str
        """

        super().__init__("")
        # https://wiki.wireshark.org/CaptureSetup/Pipes#way-1-mkfifo-on-un-x
        self.__process = subprocess.Popen(
            args=["wireshark", "-k", "--interface", "-"],
            stdin=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            preexec_fn=ignore_sigint,
        )
        self._writer = sp.RawPcapWriter(
            self.__process.stdin, sync=True, linktype=sp.DLT_IEEE802_15_4_WITHFCS
        )
        self.path = f"<wireshark@{self.__process.pid}>"

    def write(self, pkt: sp.Packet) -> None:
        """Write packet to wireshark window.

        :param pkt: Packet to be written.
        :type pkt: sp.Packet
        """
        self._writer.write(pkt)

    def close(self) -> None:
        """Close wireshark window."""
        self.__process.terminate()
