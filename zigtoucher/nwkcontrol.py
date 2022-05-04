from xdg.BaseDirectory import xdg_data_home
from typing import Union, Any, Callable, Tuple, Dict, List
import logging
import os
import random
import tempfile
import yaml
import termcolor

import zigtoucher.config as config
import zigtoucher.writer as writer
import zigtoucher.zigbee.builder as zb_b
import zigtoucher.zigbee.entity as zb_e


logger = logging.getLogger("zigtoucher.nwkcontrol")


class NwkControl:
    DEFAULT_NWKFILE: str = os.path.join(xdg_data_home, "zigtoucher/network.yml")
    CONTROL_HEADER: str = "Control"
    NEXT_HEADER: str = "Next" + zb_e.NwkAddr.HEADER
    FC_HEADER: str = "FrameCounter"
    DEVICES_HEADER: str = "Devices"

    def __init__(self, nwkfile: str, src_ieee_addr: zb_e.IEEEAddr) -> None:
        """Try to load given NWK and create empty one if it does not exist.

        :param nwkfile: Path to NWK file.
        :type nwkfile: str
        :param src_ieee_addr: Source address to be used when creating new NWK file.
        :type src_ieee_addr: zb_e.IEEEAddr
        """
        self.src_ieee_addr = src_ieee_addr
        self.src_nwk_addr = zb_e.NwkAddr(zb_e.NwkAddr.INITIATOR)
        self.next_nwk_addr = zb_e.NwkAddr(zb_e.NwkAddr.INITIATOR + 1)
        self.network = zb_e.Network(
            zb_e.ExtPanID.get_usable(),
            zb_e.PanID.get_usable(),
            zb_e.Channel.get_usable_primary(),
            key=zb_e.Key.get_usable(),
        )
        self.builder = zb_b.Builder(
            self.src_ieee_addr,
            self.src_nwk_addr,
            self.network,
        )
        self.ieee_addrs = set()
        self.nwkfile = nwkfile if nwkfile else self.DEFAULT_NWKFILE
        if not self.__read():
            self.save()

    def __str__(self) -> str:
        # prepend lines
        network = ""
        for line in str(self.network).splitlines(True):
            network += "    " + line
        return (
            termcolor.colored(f" Control \n", attrs=["bold", "reverse"])
            + f"    {self.src_ieee_addr.HEADER:<12}: {self.src_ieee_addr}\n"
            + f"    {self.src_nwk_addr.HEADER:<12}: {self.src_nwk_addr}\n"
            + f"    {self.NEXT_HEADER:<12}: {self.next_nwk_addr}\n"
            + f"    {self.FC_HEADER:<12}: 0x{self.builder.frame_counter:08x}\n"
            + "\n"
            + termcolor.colored(f" Network \n", attrs=["bold", "reverse"])
            + network
        )

    def __read(self) -> bool:
        try:
            with open(self.nwkfile, "r") as nwk_file:
                try:
                    yml = yaml.safe_load(nwk_file)
                except yaml.YAMLError as e:
                    raise ConfigError(f"{e}", "yml")
        except FileNotFoundError:
            return False
        if not yml:
            return False

        def parse_value(
            dictionary: Any,
            who: str,
            types: Union[type, Tuple[type]],
            convert: Callable = None,
            *args,
            **kwargs,
        ):
            if not config.key_exists(dictionary, who):
                raise config.ConfigError("missing", who)
            val = config.key_get(dictionary, who)
            if not isinstance(val, types):
                raise config.ConfigError("invalid data type", who)
            if convert:
                try:
                    val = convert(val, *args, **kwargs)
                except (TypeError, ValueError) as e:
                    raise config.ConfigError(f"{e}", who)
            return val

        try:
            self.__deserialize_control(yml, parse_value)
            self.__deserialize_network(yml, parse_value)
        except config.ConfigError as e:
            logger.error(f"{e.who}: {e}")

        return True

    def is_full(self) -> bool:
        return self.next_nwk_addr == zb_e.NwkAddr.MAX + 1

    def add_device(self, ieee_addr: zb_e.IEEEAddr) -> bool:
        """Add device if not full into known IEEE addresses, Network instance and move
        next short address counter.

        :param ieee_addr: _description_
        :type ieee_addr: zb_e.IEEEAddr
        :return: False if full, True otherwise.
        :rtype: bool
        """
        if self.is_full():
            return False
        self.ieee_addrs.add(ieee_addr.get())
        self.network.devices[self.next_nwk_addr.get()] = zb_e.IEEEAddr(ieee_addr.get())
        self.next_nwk_addr.set(self.next_nwk_addr.get() + 1)
        return True

    def save(self) -> None:
        """Save self using NwkControl.save_network()."""
        NwkControl.save_network(
            self.network,
            self.src_ieee_addr,
            self.src_nwk_addr,
            self.next_nwk_addr,
            self.builder.frame_counter,
            self.nwkfile,
        )

    @staticmethod
    def _serialize_control(
        src_ieee_addr: zb_e.IEEEAddr,
        next_nwk_addr: int,
        frame_counter: int,
        src_nwk_addr: zb_e.NwkAddr = None,
    ) -> Dict:
        return {
            zb_e.IEEEAddr.HEADER: str(src_ieee_addr),
            zb_e.NwkAddr.HEADER: str(src_nwk_addr)
            if src_nwk_addr
            else zb_e.NwkAddr(zb_e.NwkAddr.INITIATOR),
            NwkControl.NEXT_HEADER: str(next_nwk_addr),
            NwkControl.FC_HEADER: f"0x{frame_counter:08x}",
        }

    def __deserialize_control(self, yml: Any, parse_value: Callable) -> None:
        self.src_ieee_addr = parse_value(
            yml,
            f"{self.CONTROL_HEADER}.{zb_e.IEEEAddr.HEADER}",
            (str),
            zb_e.IEEEAddr.from_str,
        )
        self.src_nwk_addr = parse_value(
            yml,
            f"{self.CONTROL_HEADER}.{zb_e.NwkAddr.HEADER}",
            (str),
            zb_e.NwkAddr.from_str,
        )
        self.next_nwk_addr = parse_value(
            yml,
            f"{self.CONTROL_HEADER}.{self.NEXT_HEADER}",
            (str),
            zb_e.NwkAddr.from_str,
        )
        self.builder = zb_b.Builder(
            self.src_ieee_addr,
            self.src_nwk_addr,
            self.network,
            frame_counter=parse_value(
                yml,
                f"{self.CONTROL_HEADER}.{self.FC_HEADER}",
                (str),
                config.to_int,
                vmin=0,
                vmax=0xFFFFFFFF,
            ),
        )

    @staticmethod
    def _serialize_devices(network: zb_e.Network) -> Tuple[List, int]:
        # we support saving devices per nwk_addr or per ieee_addr
        devices = []
        highest_nwk_addr = zb_e.NwkAddr.INITIATOR

        if not network.devices:  # fastpath
            return devices, highest_nwk_addr

        value = random.choice(list(network.devices.values()))

        if isinstance(value, zb_e.IEEEAddr):
            for nwk_addr, ieee_addr in network.devices.items():
                if nwk_addr is None or ieee_addr.get() is None:
                    continue
                if nwk_addr > highest_nwk_addr:
                    highest_nwk_addr = nwk_addr
                devices.append(
                    {
                        zb_e.NwkAddr.HEADER: str(zb_e.NwkAddr(nwk_addr)),
                        zb_e.IEEEAddr.HEADER: str(ieee_addr),
                    }
                )
        elif isinstance(value, zb_e.NwkAddr):
            for ieee_addr, nwk_addr in network.devices.items():
                if nwk_addr.get() is None or ieee_addr is None:
                    continue
                if nwk_addr.get() > highest_nwk_addr:
                    highest_nwk_addr = nwk_addr.get()
                devices.append(
                    {
                        zb_e.NwkAddr.HEADER: str(nwk_addr),
                        zb_e.IEEEAddr.HEADER: str(zb_e.IEEEAddr(ieee_addr)),
                    }
                )

        return devices, highest_nwk_addr

    def __deserialize_devices(self, yml: Any, parse_value: Callable) -> None:
        devices = parse_value(
            yml, f"{zb_e.Network.HEADER}.{self.DEVICES_HEADER}", (list)
        )
        for i, device in enumerate(devices):
            try:
                nwk_addr = parse_value(
                    device, zb_e.NwkAddr.HEADER, (str), zb_e.NwkAddr.from_str
                )
                ieee_addr = parse_value(
                    device, zb_e.IEEEAddr.HEADER, (str), zb_e.IEEEAddr.from_str
                )
            except config.ConfigError as e:
                raise config.ConfigError(f"{e.who}: {e}", f"device #{i}")
            self.ieee_addrs.add(ieee_addr.get())
            self.network.devices[nwk_addr.get()] = ieee_addr

    @staticmethod
    def _serialize_network(network: zb_e.Network) -> Tuple[Dict, int]:
        devices, highest_nwk_addr = NwkControl._serialize_devices(network)
        return {
            zb_e.ExtPanID.HEADER: str(network.ext_pan_id),
            zb_e.PanID.HEADER: str(network.pan_id),
            zb_e.Channel.HEADER: str(network.channel),
            zb_e.Key.HEADER: str(network.key),
            NwkControl.DEVICES_HEADER: devices,
        }, highest_nwk_addr

    def __deserialize_network(self, yml: Any, parse_value: Callable) -> None:
        self.network.ext_pan_id = parse_value(
            yml,
            f"{zb_e.Network.HEADER}.{zb_e.ExtPanID.HEADER}",
            (str),
            zb_e.ExtPanID.from_str,
        )
        self.network.pan_id = parse_value(
            yml,
            f"{zb_e.Network.HEADER}.{zb_e.PanID.HEADER}",
            (str),
            zb_e.PanID.from_str,
        )
        self.network.channel = parse_value(
            yml,
            f"{zb_e.Network.HEADER}.{zb_e.Channel.HEADER}",
            (str),
            zb_e.Channel.from_str,
        )
        if not zb_e.Channel.is_primary(self.network.channel.get()):
            raise config.ConfigError("must be primary", zb_e.Channel.HEADER)
        self.network.key = parse_value(
            yml,
            f"{zb_e.Network.HEADER}.{zb_e.Key.HEADER}",
            (str),
            zb_e.Key.from_str,
        )
        self.__deserialize_devices(yml, parse_value)

    @staticmethod
    def save_network(
        network: zb_e.Network,
        src_ieee_addr: zb_e.IEEEAddr = None,
        src_nwk_addr: zb_e.NwkAddr = None,
        next_nwk_addr: zb_e.NwkAddr = None,
        frame_counter: int = 0,
        nwkfile: str = None,
    ) -> None:
        """Create XDG Data Home if needed and serialize given Network instance into
        NWK file using yaml.safe_dump().

        :param network: Network instance to be saved.
        :type network: zb_e.Network
        :param src_ieee_addr: Source IEEE address in NWK file, defaults to None
        :type src_ieee_addr: zb_e.IEEEAddr, optional
        :param src_nwk_addr: Source short address in NWK file, defaults to None
        :type src_nwk_addr: zb_e.NwkAddr, optional
        :param next_nwk_addr: Next assigned short address in NWK file, defaults to None
        :type next_nwk_addr: zb_e.NwkAddr, optional
        :param frame_counter: Frame counter in NWK file, defaults to 0
        :type frame_counter: int, optional
        :param nwkfile: Path to NWK file to be saved, defaults to None
        :type nwkfile: str, optional
        """
        writer.Writer.create_user_data()
        with (
            tempfile.NamedTemporaryFile(
                "w",
                prefix=writer.Writer.PREFIX,
                suffix=".yml",
                delete=False,
                dir=writer.Writer.USER_DATA,
                newline="",
            )
            if not nwkfile or nwkfile == writer.Writer.RANDOM
            else open(nwkfile, "w")
        ) as _file:
            logger.info(f"writing NWK into {_file.name}")
            nwkdict, highest_nwk_addr = NwkControl._serialize_network(network)
            if highest_nwk_addr >= zb_e.NwkAddr.MAX:
                highest_nwk_addr = zb_e.NwkAddr.MAX - 2
            src_ieee_addr = (
                src_ieee_addr if src_ieee_addr else zb_e.IEEEAddr.get_usable()
            )
            src_nwk_addr = (
                src_nwk_addr if src_nwk_addr else zb_e.NwkAddr(highest_nwk_addr + 1)
            )
            next_nwk_addr = (
                next_nwk_addr if next_nwk_addr else zb_e.NwkAddr(highest_nwk_addr + 2)
            )
            yaml.safe_dump(
                {
                    NwkControl.CONTROL_HEADER: NwkControl._serialize_control(
                        src_ieee_addr, next_nwk_addr, frame_counter, src_nwk_addr
                    ),
                    zb_e.Network.HEADER: nwkdict,
                },
                _file,
                default_flow_style=False,
                sort_keys=False,
            )
