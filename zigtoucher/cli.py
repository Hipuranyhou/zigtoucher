import cmd
import logging
import shlex
import time
import termcolor

import scapy.modules.gnuradio as sp_gr

import zigtoucher.zigbee.entity as zb_e
import zigtoucher.mode as mode
import zigtoucher.transceiver as transceiver
import zigtoucher.config as config
import zigtoucher.nwkcontrol as nwkcontrol


logger = logging.getLogger("zigtoucher.cli")


def __print_help_options(options_dict: dict, *options: str) -> None:
    if not options:
        return
    print("")
    print(termcolor.colored("    # Options:", attrs=["bold"]))
    for opt in options:
        if config.key_exists(options_dict, opt):
            print(f"        [{opt:<10}] => {options_dict[opt]}")
        else:
            logger.debug(f"unknown option {opt}")


def print_cmd_help(
    options_dict: dict, what: str, example: str = "", note: str = "", *options: str
) -> None:
    print("")
    print(termcolor.colored("    # What:", attrs=["bold"]))
    print(f"        {what}")
    __print_help_options(options_dict, *options)
    if example:
        print("")
        print(termcolor.colored("    # Example:", attrs=["bold"]))
        print(f"        {example}")
    if note:
        print("")
        print(termcolor.colored("    # Note:", attrs=["bold"]))
        print(f"        {note}")
    print("")


class CLI(cmd.Cmd):
    """Custom interactive shell."""

    __MODES_STR: dict = {
        "control": "Control lighting devices in specified network",
        "exit": "Exit zigtoucher",
        "export": "Export specified KeyLog transaction packets into PCAP file",
        "keylog": "Sniff Touchlink key transactions and decrypt them",
        "reset": "Reset Touchlink enabled devices in range to factory default",
        "scan": "Scan for Touchlink enabled devices",
        "sniff": "Sniff ZigBee packets and optionally decrypt them",
        "steal": "Steal Touchlink enabled devices in range to specified network",
        "transceiver": "Set physical transceiver settings or reset to defaults",
    }

    __HELP_STR: dict = {
        "address": 'Source IEEE address of transceiver or "<random>"',
        "channels": "List of channels to cycle or {all|primary|secondary}",
        "csv": 'Path to output CSV file or "<random>"',
        "follow": "Continue in sniff mode after first catched key",
        "identdur": "Identify request duration",
        "identena": "Send identify request",
        "idx": "Transaction index to export",
        "key": "Key used for decryption",
        "nwkcreate": "Create NWK files",
        "nwkfile": "PATH to NWK file",
        "pcap": 'Path to output PCAP file or "<random>"',
        "results": "Print detailed run results",
        "rxgain": "Transceiver RX gain in dB",
        "samprate": "Transceiver samprate in samples",
        "show": "Show every PDU using Scapy show()",
        "target": "IEEE address of target",
        "timeout": "Mode timeout in seconds",
        "txgain": "Transceiver TX gain in dB",
    }

    class _Parser:
        """CLI key=value pairs parser."""

        def __init__(self) -> None:
            """Just reset all attributes to default configuration."""
            self.reset()

        def reset(self) -> None:
            """Just reset all attributes to default configuration."""
            self.timeout = config.get("modes.timeout")
            self.channels = config.get("modes.channels")
            self.results = config.get("modes.results")
            self.address = config.get("transceiver.address")
            self.rxgain = config.get("transceiver.rxgain")
            self.txgain = config.get("transceiver.txgain")
            self.samprate = config.get("transceiver.samprate")
            self.pcap = config.get("modes.pcap")
            self.csv = config.get("modes.csv")
            self.nwkfile = config.get("modes.nwkfile")
            self.target = config.get("modes.target")
            self.follow = config.get("modes.keylog.follow")
            self.nwkcreate = config.get("modes.keylog.nwkcreate")
            self.key = config.get("modes.sniff.key")
            self.show = config.get("modes.sniff.show")
            self.identena = config.get("modes.reset.identena")
            self.identdur = config.get("modes.reset.identdur")
            self.idx = 0

        def parse(self, line: str, *args: str) -> None:
            """Parse given key=value parse using config.

            :param line: String holding key=value pairs.
            :type line: str
            :raises config.ConfigError: Any option is invalid.
            """

            # get defaults
            self.reset()

            # TODO: we could probably generate this automagically...

            for arg in shlex.split(line):
                if "=" not in arg:
                    raise config.ConfigError("missing =", "arg")
                key, val = arg.split("=", 1)

                # quick checks
                if not key or not val:
                    raise config.ConfigError("missing parameter or val", "arg")
                if key not in args:
                    raise config.ConfigError("parameter unknown", key)

                if key == "timeout":
                    try:
                        self.timeout = config.to_int(val, vmin=0)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "channels":
                    try:
                        self.channels = config.to_channels(val)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "results":
                    try:
                        self.results = config.to_bool(val)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "address":
                    try:
                        self.address = zb_e.IEEEAddr.from_str(val)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "rxgain":
                    try:
                        self.rxgain = config.to_float(val, vmin=0.0)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "txgain":
                    try:
                        self.txgain = config.to_float(val, vmin=0.0)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "nwkfile":
                    self.nwkfile = val

                if key == "target":
                    try:
                        self.target = zb_e.IEEEAddr.from_str(val, False)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "pcap":
                    self.pcap = val

                if key == "csv":
                    self.csv = val

                if key == "follow":
                    try:
                        self.follow = config.to_bool(val)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "nwkcreate":
                    try:
                        self.nwkcreate = config.to_bool(val)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "key":
                    try:
                        self.key = zb_e.Key.from_str(val, random_ok=False)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "show":
                    try:
                        self.show = config.to_bool(val)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "identena":
                    try:
                        self.identena = config.to_bool(val)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "identdur":
                    try:
                        self.identdur = config.to_int(val, vmin=0x0001, vmax=0xFFFF)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

                if key == "idx":
                    try:
                        self.idx = config.to_int(val, vmin=0)
                    except (TypeError, ValueError) as e:
                        raise config.ConfigError(f"{e}", key)

    prompt = "zigtoucher> "
    intro = (
        "           _       _                   _               \n"
        "       ___(_) __ _| |_ ___  _   _  ___| |__   ___ _ __\n"
        "      |_  / |/ _` | __/ _ \| | | |/ __| '_ \ / _ \ '__|\n"
        "       / /| | (_| | || (_) | |_| | (__| | | |  __/ |\n"
        "      /___|_|\__, |\__\___/ \__,_|\___|_| |_|\___|_|\n"
        "             |___/\n"
        "\n"
        + termcolor.colored(
            "    # Advanced ZigBee Touchlink sniffer and packet sender\n",
            attrs=["bold"],
        )
        + "\n"
        + termcolor.colored(
            '    # Use "?" or "help" for available commands\n', attrs=["bold"]
        )
        + termcolor.colored(
            '    # Use "help <cmd>" for more info about given command\n', attrs=["bold"]
        )
    )
    doc_header = termcolor.colored("# Commands:", attrs=["bold"])

    def preloop(self) -> None:
        """Simulate non-interactive mode by modifying self.cmdqueue."""
        mode = config.get("mode")
        if mode and mode != "interactive":
            self.cmdqueue.append(mode)
            self.cmdqueue.append("exit")

    def emptyline(self):
        """Do not run last cmd on empty line."""
        pass

    def print_topics(self, header, cmds, cmdlen, maxcol):
        """Print known commands using custom format."""
        if not cmds:
            return
        self.stdout.write(f"    {str(header)}\n")
        for cmd in cmds:
            if config.key_exists(self.__MODES_STR, cmd):
                print(f"        {cmd:<12} => {self.__MODES_STR[cmd]}")
        self.stdout.write("\n")

    def default(self, line: str):
        """Print unknown commands using custom syntax."""
        logger.error(f'unknown syntax: "{line}"')

    def __init__(self, *args, **kwargs) -> None:
        """Init transceiver based on default configuration."""
        super().__init__(*args, **kwargs)
        self.__parser = self._Parser()
        self.__mode = None
        self.__nwkcontrol = None
        try:
            self.__transceiver = self.__init_transceiver()
        except Exception as e:
            logger.error(f"transceiver: {e}")
            raise

    def __init_transceiver(self) -> None:
        """Init transceiver based on default configuration."""
        # we do it here to prevent circular dependencies
        if config.get("transceiver.type") == transceiver.Type.SDR:
            return transceiver.SDR(
                config.get("transceiver.address"),
                config.get("transceiver.sdr.flowgraph"),
                config.get("transceiver.sdr.timeout"),
                config.get("transceiver.wireshark"),
                config.get("transceiver.pcap"),
            )
        if config.get("transceiver.type") == transceiver.Type.PCAP:
            return transceiver.PCAP(
                config.get("transceiver.address"),
                config.get("transceiver.wireshark"),
                config.get("transceiver.pcap"),
            )

    def __init_nwkcontrol(self, nwkfile: str, src_ieee_addr: zb_e.IEEEAddr) -> bool:
        """Load proviedd NWK file to prevent its reloading when run modes use the same
        one again and again.

        :param nwkfile: Path to NWK file.
        :type nwkfile: str
        :param src_ieee_addr: Source address to be used by NwkControl.
        :type src_ieee_addr: zb_e.IEEEAddr
        :return: True if loaded OK, False otherwise.
        :rtype: bool
        """
        if self.__nwkcontrol and self.__nwkcontrol.nwkfile == nwkfile:
            return True
        try:
            self.__nwkcontrol = nwkcontrol.NwkControl(nwkfile, src_ieee_addr)
            return True
        except config.ConfigError as e:
            logger.error(f"nwkcontrol: {e.who}: {e}")
        except Exception as e:
            logger.error(f"nwkcontrol: {e}")
        return False

    def do_exit(self, args):
        """Close transceiver and exit zigtoucher."""
        self.__transceiver.close()
        print("")
        return True

    def help_exit(self):
        print_cmd_help(self.__HELP_STR, self.__MODES_STR["exit"])

    do_quit = do_exit
    help_quit = help_exit
    do_EOF = do_exit
    help_EOF = help_exit

    def __do_mode(self) -> None:
        """Call mode start() method and modify self.cmdqueue if next mode requested."""
        cmd = self.__mode.start()
        if cmd:
            self.cmdqueue.append(cmd)

    __COMMON_OPTS: set = {"timeout", "channels", "results"}

    __TRANSCEIVER_OPTS: set = {"rxgain", "txgain", "samprate"}

    def do_transceiver(self, args):
        # we do it here so that user does not find out it does not work
        # after fighting with invalid arguments
        if isinstance(self.__transceiver, transceiver.PCAP):
            logger.warn("not supported for pseudotransceiver transceiver.PCAP()")
            return
        self.__parser.reset()
        try:
            self.__parser.parse(args, *self.__TRANSCEIVER_OPTS)
        except config.ConfigError as e:
            logger.error(f"{e.who}: {e}")
            return
        self.__mode = mode.Transceiver(
            self.__transceiver,
            self.__parser.rxgain,
            self.__parser.txgain,
            self.__parser.samprate,
        )
        self.__do_mode()

    def complete_transceiver(self, text, line, begidx, endidx):
        return [f"{x}=" for x in self.__TRANSCEIVER_OPTS if x.startswith(text)]

    def help_transceiver(self):
        print_cmd_help(
            self.__HELP_STR,
            self.__MODES_STR["transceiver"],
            "transceiver samprate=8000000",
            "Unspecified options will use default configuration values",
            *self.__TRANSCEIVER_OPTS,
        )

    __KEYLOG_OPTS: set = __COMMON_OPTS.union({"csv", "follow", "nwkcreate", "target"})

    def do_keylog(self, args):
        if not config.get("keys.touchlink.master"):
            logger.warn("keylog is disabled without Touchlink master key")
            return
        self.__parser.reset()
        try:
            self.__parser.parse(args, *self.__KEYLOG_OPTS)
        except config.ConfigError as e:
            logger.error(f"{e.who}: {e}")
            return
        self.__mode = mode.KeyLog(
            self.__transceiver,
            self.__parser.timeout,
            self.__parser.channels,
            self.__parser.results,
            self.__parser.csv,
            self.__parser.follow,
            self.__parser.nwkcreate,
            self.__parser.target,
        )
        self.__do_mode()

    def complete_keylog(self, text, line, begidx, endidx):
        return [f"{x}=" for x in self.__KEYLOG_OPTS if x.startswith(text)]

    def help_keylog(self):
        print_cmd_help(
            self.__HELP_STR,
            self.__MODES_STR["keylog"],
            "keylog timeout=20 follow=Off results=Yes",
            "",
            *self.__KEYLOG_OPTS,
        )

    __SNIFF_OPTS: set = __COMMON_OPTS.union({"key", "pcap", "show"})

    def do_sniff(self, args):
        self.__parser.reset()
        try:
            self.__parser.parse(args, *self.__SNIFF_OPTS)
        except config.ConfigError as e:
            logger.error(f"{e.who}: {e}")
            return
        self.__mode = mode.Sniff(
            self.__transceiver,
            self.__parser.timeout,
            self.__parser.channels,
            self.__parser.results,
            self.__parser.pcap,
            self.__parser.key,
            self.__parser.show,
        )
        self.__do_mode()

    def complete_sniff(self, text, line, begidx, endidx):
        return [f"{x}=" for x in self.__SNIFF_OPTS if x.startswith(text)]

    def help_sniff(self):
        print_cmd_help(
            self.__HELP_STR,
            self.__MODES_STR["sniff"],
            "sniff timeout=30 key=0xC0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "",
            *self.__SNIFF_OPTS,
        )

    __RESET_OPTS: set = __COMMON_OPTS.union(
        {"csv", "address", "identena", "identdur", "target"}
    )

    def do_reset(self, args):
        # we do it here so that user does not find out it does not work
        # after fighting with invalid arguments
        if isinstance(self.__transceiver, transceiver.PCAP):
            logger.warn("not supported for pseudotransceiver transceiver.PCAP()")
            return
        self.__parser.reset()
        try:
            self.__parser.parse(args, *self.__RESET_OPTS)
        except config.ConfigError as e:
            logger.error(f"{e.who}: {e}")
            return
        self.__mode = mode.Reset(
            self.__transceiver,
            self.__parser.timeout,
            self.__parser.channels,
            self.__parser.results,
            self.__parser.csv,
            self.__parser.address,
            self.__parser.identena,
            self.__parser.identdur,
            self.__parser.target,
        )
        self.__do_mode()

    def help_reset(self):
        print_cmd_help(
            self.__HELP_STR,
            self.__MODES_STR["reset"],
            "reset target=ff:11:ff:33:ff:55:ff:77",
            "",
            *self.__RESET_OPTS,
        )

    def complete_reset(self, text, line, begidx, endidx):
        return [f"{x}=" for x in self.__RESET_OPTS if x.startswith(text)]

    __SCAN_OPTS: set = __COMMON_OPTS.union({"csv", "address"})

    def do_scan(self, args):
        if isinstance(self.__transceiver, transceiver.PCAP):
            logger.warn("not supported for pseudotransceiver transceiver.PCAP()")
            return
        self.__parser.reset()
        try:
            self.__parser.parse(args, *self.__RESET_OPTS)
        except config.ConfigError as e:
            logger.error(f"{e.who}: {e}")
            return
        self.__mode = mode.Scan(
            self.__transceiver,
            self.__parser.timeout,
            self.__parser.channels,
            self.__parser.results,
            self.__parser.csv,
            self.__parser.address,
        )
        self.__do_mode()

    def help_scan(self):
        print_cmd_help(
            self.__HELP_STR,
            self.__MODES_STR["scan"],
            "scan address=00:11:22:33:44:55:66:77 channels=primary",
            "",
            *self.__SCAN_OPTS,
        )

    def complete_scan(self, text, line, begidx, endidx):
        return [f"{x}=" for x in self.__SCAN_OPTS if x.startswith(text)]

    __STEAL_OPTS: set = __COMMON_OPTS.union({"address", "nwkfile", "target"})

    def do_steal(self, args):
        if isinstance(self.__transceiver, transceiver.PCAP):
            logger.warn("not supported for pseudotransceiver transceiver.PCAP()")
            return
        if not config.get("keys.touchlink.master"):
            logger.warn("steal is disabled without touchlink master key")
            return
        self.__parser.reset()
        try:
            self.__parser.parse(args, *self.__STEAL_OPTS)
        except config.ConfigError as e:
            logger.error(f"{e.who}: {e}")
            return
        if not self.__init_nwkcontrol(self.__parser.nwkfile, self.__parser.address):
            return
        self.__mode = mode.Steal(
            self.__transceiver,
            self.__parser.timeout,
            self.__parser.channels,
            self.__parser.results,
            self.__parser.target,
            self.__nwkcontrol,
        )
        self.__do_mode()

    def complete_steal(self, text, line, begidx, endidx):
        return [f"{x}=" for x in self.__STEAL_OPTS if x.startswith(text)]

    def help_steal(self):
        print_cmd_help(
            self.__HELP_STR,
            self.__MODES_STR["steal"],
            "steal target=00:11:22:33:44:55:66:77 nwkfile=network.yml",
            "",
            *self.__STEAL_OPTS,
        )

    __CONTROL_OPTS: set = {"nwkfile"}

    def do_control(self, args):
        if isinstance(self.__transceiver, transceiver.PCAP):
            logger.warn("not supported for pseudotransceiver transceiver.PCAP()")
            return
        self.__parser.reset()
        try:
            self.__parser.parse(args, *self.__CONTROL_OPTS)
        except config.ConfigError as e:
            logger.error(f"{e.who}: {e}")
            return
        if not self.__init_nwkcontrol(self.__parser.nwkfile, self.__parser.address):
            return
        if not self.__nwkcontrol.network.devices:
            logger.warn("no devices in {self.__nwkcontrol.nwkfile}")
            return
        self.__mode = mode.Control(
            self.__transceiver,
            self.__nwkcontrol,
        )
        self.__do_mode()

    def complete_control(self, text, line, begidx, endidx):
        return [f"{x}=" for x in self.__CONTROL_OPTS if x.startswith(text)]

    def help_control(self):
        print_cmd_help(
            self.__HELP_STR,
            self.__MODES_STR["control"],
            "control nwkfile=network.yml",
            "",
            *self.__CONTROL_OPTS,
        )

    __EXPORT_OPTS: set = {"idx", "pcap"}

    def do_export(self, args):
        if self.__mode is None:
            logger.info("nothing to export")
            return
        self.__parser.reset()
        try:
            self.__parser.parse(args, *self.__EXPORT_OPTS)
        except config.ConfigError as e:
            logger.error(f"{e.who}: {e}")
            return
        self.__mode.export(self.__parser.idx, self.__parser.pcap)

    def complete_export(self, text, line, begidx, endidx):
        return [f"{x}=" for x in self.__EXPORT_OPTS if x.startswith(text)]

    def help_export(self):
        print_cmd_help(
            self.__HELP_STR,
            self.__MODES_STR["export"],
            "export idx=2",
            "",
            *self.__EXPORT_OPTS,
        )
