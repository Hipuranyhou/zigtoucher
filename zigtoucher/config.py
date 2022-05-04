from xdg.BaseDirectory import xdg_config_home
from typing import Union, Any, Callable, List, Type, Iterable, IO, Text, Tuple
import argparse
import functools
import logging
import os
import yaml

import zigtoucher.transceiver as transceiver
import zigtoucher.zigbee.entity as zb_e


logger = logging.getLogger("zigtoucher.config")


__CONFIG_NAME: str = "zigtoucher/zigtoucher.yml"
__GLOBAL_CONFIG: str = os.path.join("/usr/local/etc", __CONFIG_NAME)
__USER_CONFIG: str = os.path.join(xdg_config_home, __CONFIG_NAME)
__TOUCHLINK_MASTER_KEY_SHA256: bytes = bytes.fromhex(
    "57379035b23fed6aa2424e4791a21a13c7e9aa7881f0aa455a935f40ecbe41ff"
)


class ConfigError(Exception):
    def __init__(self, message: str, who: str) -> None:
        self.message = message
        self.who = who

    def __str__(self) -> str:
        return self.message


def __init_data() -> None:
    """Constructs default configuration dictionary."""
    global __data
    __data = {
        "config": None,
        "mode": None,
        "log": {
            "verbose": None,
            "file": None,
        },
        "keys": {
            "touchlink": {
                "master": None,
                "certification": None,
            },
            "classical": {
                "certification": None,
            },
        },
        "transceiver": {
            "type": None,
            "address": None,
            "wireshark": None,
            "pcap": None,
            "rxgain": None,
            "txgain": None,
            "samprate": None,
            "sdr": {
                "flowgraph": None,
                "timeout": None,
            },
        },
        "modes": {
            "timeout": None,
            "results": None,
            "pcap": None,
            "csv": None,
            "nwkfile": None,
            "channels": None,
            "target": None,
            "keylog": {
                "follow": None,
                "nwkcreate": None,
            },
            "sniff": {
                "key": None,
                "show": None,
            },
            "reset": {
                "identena": None,
                "identdur": None,
            },
        },
    }


def key_get(dictionary: dict, key: str) -> Any:
    """Get given key from given dictionary.

    :param dictionary: Dictionary to be searched.
    :type dictionary: dict
    :param key: Dictionary key, e.g. "modes.timeout".
    :type key: str
    :return: Given key value.
    :rtype: Any
    """
    key = key.split(".")
    if not key:
        return dictionary
    return functools.reduce(lambda d, k: d[k], key, dictionary)


def get(key: str) -> Any:
    """Get global configuration key value.

    :param key: Dictionary key, e.g. "modes.timeout".
    :type key: str
    :raises ConfigError: Config not initialized.
    :return: Given key value.
    :rtype: Any
    """
    if "__data" not in globals():
        raise ConfigError("config not initialized", "get")
    return key_get(__data, key)


def __set(key: str, val: Any, overwrite: bool = False) -> None:
    """Set key in global config dictionary.

    :param key: Dictionary key, e.g. "modes.timeout".
    :type key: str
    :param val: Value to be set at key.
    :type val: Any
    :param overwrite: Overwrite values other than None, defaults to False
    :type overwrite: bool, optional
    """
    global __data
    target = __data
    key = key.split(".")
    for k in key[:-1]:
        target = target[k]
    if target[key[-1]] is not None and not overwrite:
        return
    target[key[-1]] = val


def key_exists(dictionary: dict, key: str) -> bool:
    """Search dictionary for given key existence.

    :param dictionary: Dictionary to be searched.
    :type dictionary: dict
    :param key: Dictionary key, e.g. "modes.timeout".
    :type key: str
    :return: True if exists, False otherwise.
    :rtype: bool
    """
    key = key.split(".")
    try:
        functools.reduce(lambda d, k: d[k], key, dictionary)
    except (KeyError, TypeError):
        return False
    return True


def __set_defaults() -> None:
    """Set global configuration None values to their defaults."""
    __set("config", "")
    __set("mode", "interactive")
    __set("log.verbose", True)
    __set("log.file", None)
    __set("keys.touchlink.master", zb_e.Key())
    __set(
        "keys.touchlink.certification",
        zb_e.Key.from_str("0xC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    )
    __set(
        "keys.classical.certification",
        zb_e.Key.from_str("0xD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"),
    )
    __set("transceiver.type", transceiver.Type.SDR)
    __set("transceiver.address", zb_e.IEEEAddr.from_str("<random>"))
    __set("transceiver.wireshark", False)
    __set("transceiver.pcap", None)
    __set("transceiver.rxgain", 30.0)
    __set("transceiver.txgain", 89.0)
    __set("transceiver.samprate", 4000000)
    __set("transceiver.sdr.flowgraph", "zigtoucher")
    __set("transceiver.sdr.timeout", 20)
    __set("modes.timeout", 60)
    __set("modes.results", True)
    __set("modes.pcap", None)
    __set("modes.csv", None)
    __set("modes.nwkfile", None)
    __set("modes.channels", [11])
    __set("modes.target", zb_e.IEEEAddr())
    __set("modes.keylog.follow", False)
    __set("modes.keylog.nwkcreate", True)
    __set("modes.sniff.key", zb_e.Key())
    __set("modes.sniff.show", False)
    __set("modes.reset.identena", True)
    __set("modes.reset.identdur", 0x0003)


def __determine_file_path() -> str:
    """Determine which of the 3 config files to use.

    :return: Path to chosen config file, empty string if not config found.
    :rtype: str
    """
    path = get("config")
    if path:
        return path
    # fallback to our configs
    test_path = lambda p: os.path.isfile(p) and os.access(p, os.R_OK)
    if test_path(__USER_CONFIG):
        __set("config", __USER_CONFIG)
        return __USER_CONFIG
    elif test_path(__GLOBAL_CONFIG):
        __set("config", __GLOBAL_CONFIG)
        return __GLOBAL_CONFIG
    return ""  # no config found


def __to_mode(val: str) -> str:
    """Check if given string is non-interactive enabled mode name.

    :param val: String to be checked.
    :type val: str
    :raises ValueError: Not a valid non-interactive mode.
    :return: val
    :rtype: str
    """
    if not val in {"interactive", "keylog", "sniff", "reset", "steal", "scan"}:
        raise ValueError("must be one of {interactive|keylog|sniff|reset|steal|scan}")
    return val


def to_bool(val: Union[str, bool]) -> bool:
    """Check if given value is boolean or string with our specified boolean.

    :param val: Value to be checked.
    :type val: Union[str, bool]
    :raises ValueError: Not valid boolean.
    :return: Bool value of val.
    :rtype: bool
    """
    if isinstance(val, bool):
        return val
    if not val:
        raise ValueError("must be one of {yes|no|y|n|true|false|on|off}")
    val = val.lower()
    if val == "yes" or val == "y" or val == "true" or val == "on":
        return True
    elif val == "no" or val == "n" or val == "false" or val == "off":
        return False
    else:
        raise ValueError("must be one of {yes|no|y|n|true|false|on|off}")


def to_int(val: Union[str, int], vmin: int = None, vmax: int = None) -> int:
    """Transform given value to integer with optional bounds check.

    :param val: Value to be transformed.
    :type val: Union[str, int]
    :param vmin: Lowest possible value, defaults to None
    :type vmin: int, optional
    :param vmax: Highest possible value, defaults to None
    :type vmax: int, optional
    :raises ValueError: Invalid integer or not in given range.
    :return: Integer value of val.
    :rtype: int
    """
    if isinstance(val, str):
        try:
            val = int(val, base=0)
        except (TypeError, ValueError):
            raise
    if vmin is not None and val < vmin:
        raise ValueError(f"must be >= {vmin}")
    if vmax is not None and val > vmax:
        raise ValueError(f"must be <= {vmax}")
    return val


def to_float(val: Union[str, float], vmin: float = None, vmax: float = None) -> float:
    """Transform given value to float with optional bounds check.

    :param val: Value to be transformed.
    :type val: Union[str, float]
    :param vmin: Lowest possible value, defaults to None
    :type vmin: float, optional
    :param vmax: Highest possible value, defaults to None
    :type vmax: float, optional
    :raises ValueError: Invalid float or not in given range.
    :return: Float value of val.
    :rtype: float
    """
    if isinstance(val, str):
        try:
            val = float(val)
        except (TypeError, ValueError):
            raise
    if vmin is not None and val < vmin:
        raise ValueError(f"must be >= {vmin}")
    if vmax is not None and val > vmax:
        raise ValueError(f"must be <= {vmax}")
    return val


def to_channels(val: Union[str, List[int]]) -> List[int]:
    """Transform given list ("11,22,13") to list of ZigBee channels.

    :param val: Value to be checked.
    :type val: Union[str, List[int]]
    :raises ValueError: Invalid list or channel.
    :return: List of ZigBee channels.
    :rtype: List[int]
    """
    if not val:
        raise ValueError("cannot be empty")
    if isinstance(val, list):
        channels = set(val)
    if isinstance(val, str):
        if val == "primary":
            return zb_e.Channel.PRIMARY
        elif val == "secondary":
            return zb_e.Channel.SECONDARY
        elif val == "all":
            return zb_e.Channel.ALL
        else:
            channels = set()
            for channel in val.split(","):
                channels.add(to_int(channel))
    for channel in channels:
        if not zb_e.Channel.is_usable(channel):
            raise ValueError(f"invalid channel {channel}")
    return list(channels)


def __build_argv_parser() -> argparse.ArgumentParser:
    """Build argparse.ArgumentParser with all possible CLI switches."""
    parser = argparse.ArgumentParser(
        description="ZigBee Touchlink sniffer and packet sender"
    )
    parser.add_argument(
        "-c",
        "--config",
        action="store",
        dest="config",
        metavar="PATH",
        type=str,
        help="Path to custom configuration file",
    )
    parser.add_argument(
        "-m",
        "--mode",
        action="store",
        dest="mode",
        metavar="MODE",
        type=str,
        help="Mode to run {interactive|keylog|sniff|reset|steal}",
    )
    parser.add_argument(
        "-v",
        "--log-verbose",
        action="store",
        dest="log.verbose",
        metavar="BOOL",
        type=str,
        help="Enable verbose logging and exceptions",
    )
    parser.add_argument(
        "--log-file",
        action="store",
        dest="log.file",
        metavar="PATH",
        type=str,
        help="Path to log file",
    )
    parser.add_argument(
        "--keys-touchlink-master",
        action="store",
        dest="keys.touchlink.master",
        metavar="HEX:128",
        type=str,
        help="128-bit hexstring with Touchlink commissioning master key",
    )
    parser.add_argument(
        "--keys-touchlink-certification",
        action="store",
        dest="keys.touchlink.certification",
        metavar="HEX:128",
        type=str,
        help="128-bit hexstring with Touchlink commissioning certification key",
    )
    parser.add_argument(
        "--keys-classical-certification",
        action="store",
        dest="keys.classical.certification",
        metavar="HEX:128",
        type=str,
        help="128-bit hexstring with Classical commissioning certificatin key",
    )
    parser.add_argument(
        "-t",
        "--transceiver-type",
        action="store",
        dest="transceiver.type",
        metavar="TYPE",
        type=str,
        help="Type of transceiver to be used {sdr|pcap}",
    )
    parser.add_argument(
        "-a",
        "--transceiver-address",
        action="store",
        dest="transceiver.address",
        metavar="ADDR:64",
        type=str,
        help="64-bit IEEE address for sending packets",
    )
    parser.add_argument(
        "-w",
        "--transceiver-wireshark",
        action="store",
        dest="transceiver.wireshark",
        metavar="BOOL",
        type=str,
        help="Should Wireshark window be opened",
    )
    parser.add_argument(
        "-p",
        "--transceiver-pcap",
        action="store",
        dest="transceiver.pcap",
        metavar="PATH",
        type=str,
        help="Should PCAP for this transceiver be used",
    )
    parser.add_argument(
        "--transceiver-rxgain",
        action="store",
        dest="transceiver.rxgain",
        metavar="DB",
        type=str,
        help="RX gain of transceiver",
    )
    parser.add_argument(
        "--transceiver-txgain",
        action="store",
        dest="transceiver.txgain",
        metavar="DB",
        type=str,
        help="TX gain of transceiver",
    )
    parser.add_argument(
        "--transceiver-samprate",
        action="store",
        dest="transceiver.samprate",
        metavar="SAMPLES",
        type=str,
        help="Sample rate of transceiver",
    )
    parser.add_argument(
        "--transceiver-sdr-flowgraph",
        action="store",
        dest="transceiver.sdr.flowgraph",
        metavar="STR",
        type=str,
        help="GNU Radio flowgraph of SDR transceiver",
    )
    parser.add_argument(
        "--transceiver-sdr-timeout",
        action="store",
        dest="transceiver.sdr.timeout",
        metavar="SECS",
        type=str,
        help="GNU Radio flowgraph startup timeout",
    )
    parser.add_argument(
        "-T",
        "--modes-timeout",
        action="store",
        dest="modes.timeout",
        metavar="SECS",
        type=str,
        help="Default timeout for run modes",
    )
    parser.add_argument(
        "--modes-results",
        action="store",
        dest="modes.results",
        metavar="BOOL",
        type=str,
        help="Should verbose results of run modes be printed",
    )
    parser.add_argument(
        "--modes-pcap",
        action="store",
        dest="modes.pcap",
        metavar="PATH",
        type=str,
        help="Output PCAP file for run modes",
    )
    parser.add_argument(
        "--modes-csv",
        action="store",
        dest="modes.csv",
        metavar="PATH",
        type=str,
        help="CSV file for writing results",
    )
    parser.add_argument(
        "--modes-nwkfile",
        action="store",
        dest="modes.nwkfile",
        metavar="PATH",
        type=str,
        help="Path to custom NWK file",
    )
    parser.add_argument(
        "--modes-channels",
        action="store",
        dest="modes.channels",
        metavar="CHANNELS",
        type=str,
        help="Channels to cycle through in run modes",
    )
    parser.add_argument(
        "--modes-target",
        action="store",
        dest="modes.target",
        metavar="ADDR:64",
        type=str,
        help="Target 64-bit IEEE address for modes {reset|steal}",
    )
    parser.add_argument(
        "--modes-keylog-follow",
        action="store",
        dest="modes.keylog.follow",
        metavar="BOOL",
        type=str,
        help="Should keylog mode follow to sniff mode",
    )
    parser.add_argument(
        "--modes-keylog-nwkcreate",
        action="store",
        dest="modes.keylog.nwkcreate",
        metavar="BOOL",
        type=str,
        help="Should sniffed NWK files be created in keylog mode",
    )
    parser.add_argument(
        "--modes-sniff-key",
        action="store",
        dest="modes.sniff.key",
        metavar="HEX:128",
        type=str,
        help="Key for decryption in sniff mode",
    )
    parser.add_argument(
        "--modes-sniff-show",
        action="store",
        dest="modes.sniff.show",
        metavar="BOOL",
        type=str,
        help="Show packets during sniff mode using Scapy show()",
    )
    parser.add_argument(
        "--modes-reset-identena",
        action="store",
        dest="modes.reset.identena",
        metavar="BOOL",
        type=str,
        help="Should identify packet be sent in reset mode",
    )
    parser.add_argument(
        "--modes-reset-identdur",
        action="store",
        dest="modes.reset.identdur",
        metavar="SECS",
        type=str,
        help="Duration of identify packet in reset mode",
    )
    return parser


def __parse_argv() -> None:
    """Parse CLI switches using __build_argv_parser() and set with highest priority.

    :raises ConfigError: Invalid value specified.
    """

    parser = __build_argv_parser()
    parsed = parser.parse_args()

    def parse_value(
        parsed: Any,
        who: str,
        convert: Callable = None,
        *args,
        **kwargs,
    ) -> None:
        val = getattr(parsed, who)
        if not val:
            return
        cli_who = f"--{who.replace('.', '-')}"
        try:
            __set(
                who,
                convert(val, *args, **kwargs) if convert is not None else val,
                True,
            )
        except (TypeError, ValueError) as e:
            raise ConfigError(f"{e}", cli_who)

    parse_value(parsed, "config")
    parse_value(parsed, "mode", __to_mode)
    parse_value(parsed, "log.verbose", to_bool)
    parse_value(parsed, "log.file")
    parse_value(
        parsed,
        "keys.touchlink.master",
        zb_e.Key.from_str,
        khash=__TOUCHLINK_MASTER_KEY_SHA256,
    )
    parse_value(parsed, "keys.touchlink.certification", zb_e.Key.from_str)
    parse_value(parsed, "keys.classical.certification", zb_e.Key.from_str)
    parse_value(parsed, "transceiver.type", transceiver.Type.from_str)
    parse_value(parsed, "transceiver.address", zb_e.IEEEAddr.from_str)
    parse_value(parsed, "transceiver.wireshark", to_bool)
    parse_value(parsed, "transceiver.pcap")
    parse_value(parsed, "transceiver.rxgain", to_float, vmin=0.0)
    parse_value(parsed, "transceiver.txgain", to_float, vmin=0.0)
    parse_value(parsed, "transceiver.samprate", to_int, vmin=1)
    parse_value(parsed, "transceiver.sdr.flowgraph")
    parse_value(parsed, "transceiver.sdr.timeout", to_int, vmin=0)
    parse_value(parsed, "modes.timeout", to_int, vmin=0)
    parse_value(parsed, "modes.results", to_bool)
    parse_value(parsed, "modes.target", zb_e.IEEEAddr.from_str, random_ok=False)
    parse_value(parsed, "modes.pcap")
    parse_value(parsed, "modes.csv")
    parse_value(parsed, "modes.nwkfile")
    parse_value(parsed, "modes.channels", to_channels)
    parse_value(parsed, "modes.keylog.follow", to_bool)
    parse_value(parsed, "modes.keylog.nwkcreate", to_bool)
    parse_value(parsed, "modes.sniff.key", zb_e.Key.from_str)
    parse_value(parsed, "modes.sniff.show", to_bool)
    parse_value(parsed, "modes.reset.identena", to_bool)
    parse_value(parsed, "modes.reset.identdur", to_int, vmin=0x0001, vmax=0xFFFF)

    if get("transceiver.type") == transceiver.Type.PCAP and not get("transceiver.pcap"):
        raise ConfigError("missing transceiver.pcap", "transceiver.type")


def __parse_file(stream: Union[bytes, IO[bytes], Text, IO[Text]]) -> None:
    """Parse config file values using yaml.safe_load and set with lowest priority.

    :raises ConfigError: Invalid value specified.
    """

    try:
        yml = yaml.safe_load(stream)
    except yaml.YAMLError as e:
        raise ConfigError(f"{e}", "yml")

    if not yml:
        logger.warn("file: empty")
        return

    def parse_value(
        dictionary: Any,
        who: str,
        types: Union[type, Tuple[type]],
        convert: Callable = None,
        *args,
        **kwargs,
    ) -> None:
        # argv values have precedence over file
        if get(who) is not None or not key_exists(dictionary, who):
            return
        val = key_get(dictionary, who)
        if not isinstance(val, types):
            raise ConfigError("invalid data type", who)
        try:
            __set(who, convert(val, *args, **kwargs) if convert is not None else val)
        except (TypeError, ValueError) as e:
            raise ConfigError(f"{e}", who)

    parse_value(yml, "mode", (str), __to_mode)
    parse_value(yml, "log.verbose", (str, bool), to_bool)
    parse_value(yml, "log.file", (str))
    parse_value(
        yml,
        "keys.touchlink.master",
        (str),
        zb_e.Key.from_str,
        khash=__TOUCHLINK_MASTER_KEY_SHA256,
    )
    parse_value(yml, "keys.touchlink.certification", (str), zb_e.Key.from_str)
    parse_value(yml, "keys.classical.certification", (str), zb_e.Key.from_str)
    parse_value(yml, "transceiver.type", (str), transceiver.Type.from_str)
    parse_value(yml, "transceiver.address", (str), zb_e.IEEEAddr.from_str)
    parse_value(yml, "transceiver.wireshark", (str, bool), to_bool)
    parse_value(yml, "transceiver.pcap", (str))
    parse_value(yml, "transceiver.rxgain", (str, float), to_float, vmin=0.0)
    parse_value(yml, "transceiver.txgain", (str, float), to_float, vmin=0.0)
    parse_value(yml, "transceiver.samprate", (str, int), to_int, vmin=1)
    parse_value(yml, "transceiver.sdr.flowgraph", (str))
    parse_value(yml, "transceiver.sdr.timeout", (str, int), to_int, vmin=0)
    parse_value(yml, "modes.timeout", (str, int), to_int, vmin=0)
    parse_value(yml, "modes.results", (str, bool), to_bool)
    parse_value(yml, "modes.target", (str), zb_e.IEEEAddr.from_str, random_ok=False)
    parse_value(yml, "modes.pcap", (str))
    parse_value(yml, "modes.csv", (str))
    parse_value(yml, "modes.channels", (str, list), to_channels)
    parse_value(yml, "modes.nwkfile", (str))
    parse_value(yml, "modes.keylog.follow", (str, bool), to_bool)
    parse_value(yml, "modes.keylog.nwkcreate", (str, bool), to_bool)
    parse_value(yml, "modes.sniff.key", (str), zb_e.Key.from_str)
    parse_value(yml, "modes.sniff.show", (str, bool), to_bool)
    parse_value(yml, "modes.reset.identena", (str, bool), to_bool)
    parse_value(
        yml, "modes.reset.identdur", (str, int), to_int, vmin=0x0001, vmax=0xFFFF
    )

    if get("transceiver.type") == transceiver.Type.PCAP and not get("transceiver.pcap"):
        raise ConfigError("missing transceiver.pcap", "transceiver.type")


def parse() -> None:
    """Init global configuration dictionary and parse CLI switches and config file."""

    if "__data" in globals():  # we do not support reconfig in runtime, no need to
        logger.debug("cannot run parse() twice")
        return

    __init_data()

    try:
        __parse_argv()
    except ConfigError as e:
        logger.error(f"cli: {e.who}: {e}")
        raise

    path = __determine_file_path()
    if path:
        try:
            with open(path, "r") as stream:
                __parse_file(stream)
        except ConfigError as e:
            logger.error(f"file: {e.who}: {e}")
            raise
        except Exception as e:
            logger.error(f"file: {e}")
            raise
    else:
        logger.info("file: not used")

    __set_defaults()  # set all None values to their defaults
