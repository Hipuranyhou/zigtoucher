import logging
import random
import secrets

import scapy.all as sp

import zigtoucher.zigbee.crypto as zb_c
import zigtoucher.zigbee.entity as zb_e


logger = logging.getLogger("zigtoucher.zigbee.builder")


# TODO: If more commands are needed, clusters should be separated


class Builder:
    def __init__(
        self,
        src_ieee_addr: zb_e.IEEEAddr,
        src_nwk_addr: zb_e.NwkAddr,
        network: zb_e.Network,
        mac_seqnum: int = 0,
        nwk_seqnum: int = 0,
        frame_counter: int = 0,
        aps_counter: int = 0,
        zdp_seqnum: int = 0,
        zcl_seqnum: int = 0,
    ) -> None:
        """Save all attrbiutes used for building general ZigBee packets.

        :param src_ieee_addr: Source IEEE address.
        :type src_ieee_addr: zb_e.IEEEAddr
        :param src_nwk_addr: Source short address.
        :type src_nwk_addr: zb_e.NwkAddr
        :param network: Network instance used for comms.
        :type network: zb_e.Network
        :param mac_seqnum: Specific MAC seqnum, defaults to 0
        :type mac_seqnum: int, optional
        :param nwk_seqnum: Specific NWK seqnum, defaults to 0
        :type nwk_seqnum: int, optional
        :param frame_counter: Specific frame counter, defaults to 0
        :type frame_counter: int, optional
        :param aps_counter: Specific APS counter, defaults to 0
        :type aps_counter: int, optional
        :param zdp_seqnum: Specific ZDP seqnum, defaults to 0
        :type zdp_seqnum: int, optional
        :param zcl_seqnum: Specific ZCL seqnum, defaults to 0
        :type zcl_seqnum: int, optional
        """
        self.src_ieee_addr = src_ieee_addr
        self.src_nwk_addr = src_nwk_addr
        self.network = network
        self.mac_seqnum = mac_seqnum
        self.nwk_seqnum = nwk_seqnum
        self.frame_counter = frame_counter
        self.aps_counter = aps_counter
        self.zdp_seqnum = zdp_seqnum
        self.zcl_seqnum = zcl_seqnum
        self.last_pkt = None
        self.last_pkt_encrypted = None

    def __update_seqnums(self) -> None:
        """Move all layers seqnums with proper %."""
        self.mac_seqnum = (self.mac_seqnum + 1) % 0x100
        self.nwk_seqnum = (self.nwk_seqnum + 1) % 0x100
        if self.frame_counter < 0xFFFFFFFF:
            self.frame_counter = self.frame_counter + 1
        else:
            # TODO: rotate network key?
            logger.warn("frame counter reached maximum")
        self.aps_counter = (self.aps_counter + 1) % 0x100

    def rebuild_seqnums(self) -> sp.Packet:
        """Move all layers seqnums with proper % and return last
        packet with these new seqnums.
        """
        if not self.last_pkt:
            return None
        self.__update_seqnums()
        self.last_pkt[sp.Dot15d4FCS].seqnum = self.mac_seqnum
        self.last_pkt[sp.ZigbeeNWK].seqnum = self.nwk_seqnum
        self.last_pkt[sp.ZigbeeSecurityHeader].fc = self.frame_counter
        self.last_pkt[sp.ZigbeeAppDataPayload].counter = self.aps_counter
        return self.__build()

    def __build(self):
        """Encrypt builded packet if needed and save it as last packet."""
        if not self.last_pkt.haslayer(sp.ZigbeeSecurityHeader):
            self.last_pkt_encrypted = self.last_pkt
        else:
            self.last_pkt_encrypted = zb_c.encrypt(
                self.last_pkt, self.network.key.get()
            )
        return self.last_pkt_encrypted

    def __base(self) -> sp.Packet:
        """Build general ZigBee frame.

        Right now based on Philips implementation.

        :return: General ZigBee frame.
        :rtype: sp.Packet
        """

        mac = sp.Dot15d4FCS() / sp.Dot15d4Data()
        mac.fcf_frametype = 0b001
        mac.fcf_security = 0
        mac.fcf_pending = 0
        mac.fcf_srcaddrmode = 0b10
        mac.fcf_ackreq = 0
        mac.fcf_destaddrmode = 0b10
        mac.fcf_panidcompress = 1
        mac.seqnum = self.mac_seqnum
        mac.dest_panid = self.network.pan_id.get()
        mac.src_addr = self.src_nwk_addr.get()

        nwk = sp.ZigbeeNWK()
        nwk.flags.security = 1
        nwk.source = self.src_nwk_addr.get()
        nwk.radius = 30
        nwk.seqnum = self.nwk_seqnum

        sec = sp.ZigbeeSecurityHeader()
        sec.source = self.src_ieee_addr.get()
        sec.fc = self.frame_counter

        aps = sp.ZigbeeAppDataPayload()
        aps.frame_control = 0
        aps.counter = self.aps_counter

        self.__update_seqnums()

        return mac / nwk / sec / aps

    def zdp_device_announcement(self) -> sp.Packet:
        """Build ZDP device announcement frame.

        Right now based on Philips implementation.

        :return: ZDP device announcement frame.
        :rtype: sp.Packet
        """

        base = self.__base()

        # nwk
        base[sp.ZigbeeNWK].destination = 0xFFFD

        # aps
        base[sp.ZigbeeAppDataPayload].delivery_mode = 2
        base[sp.ZigbeeAppDataPayload].dst_endpoint = 0
        base[sp.ZigbeeAppDataPayload].cluster = 0x0013
        base[sp.ZigbeeAppDataPayload].profile = 0x0000
        base[sp.ZigbeeAppDataPayload].src_endpoint = 0

        data = sp.ZigbeeDeviceProfile() / sp.ZDPDeviceAnnce()
        data.trans_seqnum = self.zdp_seqnum
        data.nwk_addr = self.src_nwk_addr.get()
        data.ieee_addr = self.src_ieee_addr.get()
        data.allocate_address = 1
        data.receiver_on_when_idle = 1
        data.power_source = 1
        data.device_type = 1

        self.zdp_seqnum = (self.zdp_seqnum + 1) % 256

        self.last_pkt = base / data
        return self.__build()

    def zcl_identify(self, dest_nwk_addr: zb_e.NwkAddr, duration: int) -> sp.Packet:
        """Build ZCL identify frame with given duration.

        Right now based on Philips implementation.

        :return: ZCL identify frame.
        :rtype: sp.Packet
        """

        if duration < 0x0001 or duration > 0xFFFF:
            raise ValueError("duration must be >= 0x0001 and <= 0xFFFF")

        base = self.__base()

        # mac
        base[sp.Dot15d4Data].dest_addr = dest_nwk_addr.get()

        # nwk
        base[sp.ZigbeeNWK].destination = dest_nwk_addr.get()

        # aps
        base[sp.ZigbeeAppDataPayload].dst_endpoint = 0xFF  # broadcast
        base[sp.ZigbeeAppDataPayload].cluster = 0x0003
        base[sp.ZigbeeAppDataPayload].profile = 0x0104
        base[sp.ZigbeeAppDataPayload].src_endpoint = 1

        data = sp.ZigbeeClusterLibrary()
        data.zcl_frametype = 1
        data.transaction_sequence = self.zcl_seqnum
        data.command_identifier = 0x00
        data.add_payload(duration.to_bytes(2, "little"))

        self.zcl_seqnum = (self.zcl_seqnum + 1) % 256

        self.last_pkt = base / data
        return self.__build()

    def zcl_onoff(self, dest_nwk_addr: zb_e.NwkAddr, state: bool) -> sp.Packet:
        """Build ZCL OnOff frame.

        Right now based on Philips implementation.

        :return: ZCL OnOff frame.
        :rtype: sp.Packet
        """

        base = self.__base()

        # mac
        base[sp.Dot15d4Data].dest_addr = dest_nwk_addr.get()

        # nwk
        base[sp.ZigbeeNWK].destination = dest_nwk_addr.get()

        # aps
        # TODO: we should read and choose the right one endpoint
        base[sp.ZigbeeAppDataPayload].dst_endpoint = 0xFF  # broadcast
        base[sp.ZigbeeAppDataPayload].cluster = 0x0006
        base[sp.ZigbeeAppDataPayload].profile = 0x0104
        base[sp.ZigbeeAppDataPayload].src_endpoint = 1

        data = sp.ZigbeeClusterLibrary()
        data.zcl_frametype = 1
        data.transaction_sequence = self.zcl_seqnum
        data.command_identifier = 1 if state else 0

        self.zcl_seqnum = (self.zcl_seqnum + 1) % 256

        self.last_pkt = base / data
        return self.__build()

    def zcl_level_control(
        self, dest_nwk_addr: zb_e.NwkAddr, direction: bool, size: int
    ) -> sp.Packet:
        """Build ZCL level control frame with given step size.

        :return: ZCL level control frame.
        :rtype: sp.Packet
        """
        if size < 0 or size > 255:
            raise ValueError("size must be >= 0 and <= 255")

        # Right now based on Philips implementation

        base = self.__base()

        # mac
        base[sp.Dot15d4Data].dest_addr = dest_nwk_addr.get()

        # nwk
        base[sp.ZigbeeNWK].destination = dest_nwk_addr.get()

        # aps
        # TODO: we should read and choose the right one endpoint
        base[sp.ZigbeeAppDataPayload].dst_endpoint = 0xFF  # broadcast
        base[sp.ZigbeeAppDataPayload].cluster = 0x0008
        base[sp.ZigbeeAppDataPayload].profile = 0x0104
        base[sp.ZigbeeAppDataPayload].src_endpoint = 1

        data = sp.ZigbeeClusterLibrary()
        data.zcl_frametype = 1
        data.transaction_sequence = self.zcl_seqnum
        data.command_identifier = 0x02  # step
        # mode | size | move as fast as possible
        payload = [0 if direction else 1, size, 0xFF, 0xFF]
        data.add_payload(bytes(payload))

        self.zcl_seqnum = (self.zcl_seqnum + 1) % 256

        self.last_pkt = base / data
        return self.__build()
