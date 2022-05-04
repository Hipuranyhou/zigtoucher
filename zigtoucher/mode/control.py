from typing import Type, Set
import cmd
import logging
import shlex
import termcolor

import zigtoucher.cli as cli
import zigtoucher.config as config
import zigtoucher.mode.base as modebase
import zigtoucher.nwkcontrol as nwkcontrol
import zigtoucher.transceiver as transceiver
import zigtoucher.zigbee.entity as zb_e


logger = logging.getLogger("zigtoucher.mode.control")


class Control(modebase.Mode):
    """ZigBee network devices control mode."""

    class _CLI(cmd.Cmd):
        """Nested command line interface for controling devices."""

        __MODES_STR: dict = {
            "exit": "Save NWK file and exit control mode",
            "identify": "Identify device with specified duration",
            "level": "Change light brightness by specified value",
            "list": "List loaded network details",
            "power": "Turn light on or off",
        }

        __HELP_STR: dict = {
            "nwkaddr": "Short destination address",
            "action": "One of values provided in example",
            "amount": "One byte value",
            "duration": "Duration of action in seconds",
        }

        class _Parser:
            """Arguments parser for control CLI."""

            def __init__(self, _nwkcontrol: Type[nwkcontrol.NwkControl]) -> None:
                """Just call self.reset().

                :param _nwkcontrol: NwkControl instance for known NwkAddr checks.
                :type _nwkcontrol: Type[nwkcontrol.NwkControl]
                """
                self.__nwkcontrol = _nwkcontrol
                self.reset()

            def reset(self) -> None:
                """Just reset all attributes to None."""
                self.nwkaddr = None
                self.action = None
                self.amount = None
                self.duration = None
                self.have_value = False

            def parse(
                self,
                line: str,
                nwkaddr: bool,
                actions: Set[str],
                value: str,
                *args,
            ) -> None:
                """Parse line containg key=value pairs into own attributes.

                :param line: String containing all the key=value pairs.
                :type line: str
                :param nwkaddr: Is NwkAddr needed?
                :type nwkaddr: bool
                :param actions: Which values are supported by action?
                :type actions: Set[str]
                :param value: Name of the value argument.
                :type value: str
                :raises config.ConfigError: If any argument is invalid or missing.
                """
                self.reset()

                for arg in shlex.split(line):

                    # TODO: some better way for optional vs. needed

                    # check for invalid options
                    if "=" not in arg:
                        raise config.ConfigError("missing =", "arg")
                    key, val = arg.split("=", 1)
                    if not key or not val:
                        raise config.ConfigError("missing key or value", "arg")
                    if key not in args:
                        raise config.ConfigError("key unknown", key)

                    if nwkaddr and key == "nwkaddr":
                        try:
                            self.nwkaddr = zb_e.NwkAddr.from_str(val, False)
                        except (TypeError, ValueError) as e:
                            raise config.ConfigError(f"{e}", key)
                        if self.nwkaddr.get() not in self.__nwkcontrol.network.devices:
                            raise config.ConfigError(f"unknown", key)

                    if actions and key == "action":
                        if val not in actions:
                            raise config.ConfigError("invalid", key)
                        self.action = val

                    if value == "amount" and key == "amount":
                        try:
                            self.amount = config.to_int(val, vmin=0, vmax=255)
                        except (TypeError, ValueError) as e:
                            raise config.ConfigError(f"{e}", key)
                        self.have_value = True

                    if value == "duration" and key == "duration":
                        try:
                            self.duration = config.to_int(val, vmin=0x0001, vmax=0xFFFF)
                        except (TypeError, ValueError) as e:
                            raise config.ConfigError(f"{e}", key)
                        self.have_value = True

                # check for optionals
                if nwkaddr and not self.nwkaddr:
                    raise config.ConfigError("missing", "nwkaddr")
                if actions and not self.action:
                    raise config.ConfigError("missing", "action")
                if value and not self.have_value:
                    raise config.ConfigError("missing", value)

        prompt = "zigtoucher[control]> "
        intro = ""
        doc_header = termcolor.colored("# Commands:", attrs=["bold"])

        def emptyline(self):
            """Do not run last cmd on empty line."""
            pass

        def print_topics(self, header, cmds, cmdlen, maxcol):
            """Print known commands using custom format from cmd.Cmd."""
            if not cmds:
                return
            self.stdout.write(f"    {str(header)}\n")
            for cmd in cmds:
                if config.key_exists(self.__MODES_STR, cmd):
                    print(f"        {cmd:<12} => {self.__MODES_STR[cmd]}")
            self.stdout.write("\n")

        def default(self, line: str):
            """Print unknown command using custom format from cmd.Cmd."""
            logger.error(f'unknown syntax: "{line}"')

        def __init__(
            self,
            _transceiver: Type[transceiver._Transceiver],
            _nwkcontrol: Type[nwkcontrol.NwkControl],
            *args,
            **kwargs,
        ) -> None:
            """Just save all needed attributes by commands.

            :param _transceiver: Transceiver to be used for comms.
            :type _transceiver: Type[transceiver._Transceiver]
            :param _nwkcontrol: NwkControl to be used by commands.
            :type _nwkcontrol: Type[nwkcontrol.NwkControl]
            """
            super().__init__(*args, **kwargs)
            self._transceiver = _transceiver
            self.__nwkcontrol = _nwkcontrol
            self.__parser = self._Parser(_nwkcontrol)

        def do_exit(self, args):
            """Save given NwkControl instance to NWK file and return to main CLI."""
            try:
                self.__nwkcontrol.save()
            except Exception as e:
                logger.error(f"nwkcontrol: {e}")
            return True

        def help_exit(self):
            print_cmd_help(self.__HELP_STR, self.__MODES_STR["exit"])

        do_quit = do_exit
        help_quit = help_exit
        do_EOF = do_exit
        help_EOF = help_exit

        __COMMON_OPTS: set = {"nwkaddr"}

        def do_list(self, args):
            """Just print given NwkControl instance."""
            print("")
            print(self.__nwkcontrol)
            print("")

        def help_list(self):
            cli.print_cmd_help(
                self.__HELP_STR,
                self.__MODES_STR["list"],
                "list",
                "",
            )

        __POWER_OPTS: set = __COMMON_OPTS.union({"action"})

        def do_power(self, args):
            """Control given network device on/off."""
            self.__parser.reset()
            try:
                self.__parser.parse(args, True, {"on", "off"}, "", *self.__POWER_OPTS)
            except config.ConfigError as e:
                logger.error(f"{e.who}: {e}")
                return
            pkt = self.__nwkcontrol.builder.zcl_onoff(
                self.__parser.nwkaddr, self.__parser.action == "on"
            )
            self._transceiver.send(pkt)

        def complete_power(self, text, line, begidx, endidx):
            return [f"{x}=" for x in self.__POWER_OPTS if x.startswith(text)]

        def help_power(self):
            cli.print_cmd_help(
                self.__HELP_STR,
                self.__MODES_STR["power"],
                "level nwkaddr=0x0005 action={on|off}",
                "",
                *self.__POWER_OPTS,
            )

        __LEVEL_OPTS: set = __COMMON_OPTS.union({"action", "amount"})

        def do_level(self, args):
            """Control given network device brightness."""
            self.__parser.reset()
            try:
                self.__parser.parse(
                    args, True, {"up", "down"}, "amount", *self.__LEVEL_OPTS
                )
            except config.ConfigError as e:
                logger.error(f"{e.who}: {e}")
                return
            pkt = self.__nwkcontrol.builder.zcl_level_control(
                self.__parser.nwkaddr,
                self.__parser.action == "up",
                self.__parser.amount,
            )
            self._transceiver.send(pkt)

        def complete_level(self, text, line, begidx, endidx):
            return [f"{x}=" for x in self.__LEVEL_OPTS if x.startswith(text)]

        def help_level(self):
            cli.print_cmd_help(
                self.__HELP_STR,
                self.__MODES_STR["level"],
                "level nwkaddr=0x0004 action={up|down} amount=100",
                "",
                *self.__LEVEL_OPTS,
            )

        __IDENTIFY_OPTS: set = __COMMON_OPTS.union({"duration"})

        def do_identify(self, args):
            """Let given network device do identify action."""
            self.__parser.reset()
            try:
                self.__parser.parse(
                    args, True, set(), "duration", *self.__IDENTIFY_OPTS
                )
            except config.ConfigError as e:
                logger.error(f"{e.who}: {e}")
                return
            pkt = self.__nwkcontrol.builder.zcl_identify(
                self.__parser.nwkaddr, self.__parser.duration
            )
            self._transceiver.send(pkt)

        def complete_identify(self, text, line, begidx, endidx):
            return [f"{x}=" for x in self.__IDENTIFY_OPTS if x.startswith(text)]

        def help_identify(self):
            cli.print_cmd_help(
                self.__HELP_STR,
                self.__MODES_STR["identify"],
                "identify nwkaddr=0x0003 duration=3",
                "",
                *self.__IDENTIFY_OPTS,
            )

    def __init__(
        self,
        _transceiver: Type[transceiver._Transceiver],
        _nwkcontrol: Type[nwkcontrol.NwkControl],
    ) -> None:
        """Just save all attributes neede by this CLI.

        :param _transceiver: Transcevier to be used for comms.
        :type _transceiver: Type[transceiver._Transceiver]
        :param _nwkcontrol: NwkControl instance to be used by commands.
        :type _nwkcontrol: Type[nwkcontrol.NwkControl]
        """
        super().__init__(
            _transceiver,
            0,
            [11],
            False,
            zb_e.IEEEAddr(_nwkcontrol.network.ext_pan_id.get()),
        )
        self._transceiver.set_channel(channel=_nwkcontrol.network.channel.get())
        self.__nwkcontrol = _nwkcontrol

    def _act(self) -> str:
        """Just call cmdloop() of this CLI.

        :return: Empty string.
        :rtype: str
        """
        self._CLI(self._transceiver, self.__nwkcontrol).cmdloop()
        return ""
