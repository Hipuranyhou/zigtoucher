import logging

import scapy.all as sp

import zigtoucher.zigbee.entity as zb_e
import zigtoucher.zigbee.touchlink.entity as zbt_e
import zigtoucher.zigbee.touchlink.crypto as zbt_c
import zigtoucher.config as config


logger = logging.getLogger("zigtoucher.zigbee.touchlink.builder")


class Builder:
    """Touchlink packets builder class."""

    def __init__(
        self,
        src_ieee_addr: zb_e.IEEEAddr,
        ipan_transaction_id: zbt_e.IPANTransactionID = None,
        mac_seqnum: int = 0,
        src_pan_id: zb_e.PanID = None,
    ) -> None:
        """Save source values used in builded packets.

        :param src_ieee_addr: Source address used.
        :type src_ieee_addr: zb_e.IEEEAddr
        :param ipan_transaction_id: Specific transaction ID, defaults to None
        :type ipan_transaction_id: zbt_e.IPANTransactionID, optional
        :param mac_seqnum: Specific MAC seqnum, defaults to 0
        :type mac_seqnum: int, optional
        :param src_pan_id: Specific source PAN ID, defaults to None
        :type src_pan_id: zb_e.PanID, optional
        """
        self.__src_ieee_addr = src_ieee_addr
        self.ipan_transaction_id = (
            ipan_transaction_id
            if ipan_transaction_id
            else zbt_e.IPANTransactionID.get_usable()
        )
        self.__mac_seqnum = mac_seqnum % 256
        self.__src_pan_id = src_pan_id if src_pan_id else zb_e.PanID.get_usable()
        self.__dest_ieee_addr = None
        self.__response_id = None
        self.last_pkt = None

    def __update_mac_seqnum(self) -> None:
        """Move to next MAC seqnum with % 256."""
        self.__mac_seqnum = (self.__mac_seqnum + 1) % 256

    def rebuild_mac_seqnum(self) -> sp.Packet:
        """Move to next MAC seqnum with % 256 and return
        last packet with this new MAC seqnum.
        """
        if not self.last_pkt:
            return None
        self.__update_mac_seqnum()
        self.last_pkt[sp.Dot15d4FCS].seqnum = self.__mac_seqnum
        return self.last_pkt

    def update_dest_ieee_addr(self, dest_ieee_addr: zb_e.IEEEAddr) -> None:
        """Set destination address used by packtes after scan request.

        :param dest_ieee_addr: Destination address.
        :type dest_ieee_addr: zb_e.IEEEAddr
        """
        self.__dest_ieee_addr = dest_ieee_addr

    def update_response_id(self, response_id: int) -> None:
        """Set response ID used by packtes after scan request.

        :param response_id: Response ID.
        :type response_id: int
        """
        self.__response_id = response_id

    def __base(self) -> sp.Packet:
        """Build general inter-PAN frame specified by ZigBee Cluster Library 13-49.

        :return: General inter-PAN frame.
        :rtype: sp.Packet
        """
        mac = sp.Dot15d4FCS() / sp.Dot15d4Data()
        mac.fcf_frametype = 0b001
        mac.fcf_security = 0
        mac.fcf_pending = 0
        mac.fcf_srcaddrmode = 0b11
        mac.seqnum = self.__mac_seqnum
        mac.dest_panid = 0xFFFF
        mac.src_panid = self.__src_pan_id.get()
        mac.src_addr = self.__src_ieee_addr.get()

        nwk = sp.ZigbeeNWKStub()
        nwk.frametype = 0b11

        aps = sp.ZigbeeAppDataPayloadStub()
        aps.frametype = 0b11
        aps.cluster = 0x1000
        aps.profile = 0xC05E

        zcl = sp.ZigbeeZLLCommissioningCluster()
        zcl.zcl_frametype = 0b01
        zcl.disable_default_response = 1
        zcl.manufacturer_specific = 0
        zcl.transaction_sequence = 0

        self.__update_mac_seqnum()

        return mac / nwk / aps / zcl

    def scan_request(self) -> sp.Packet:
        """Build scan request frame specified by ZigBee Cluster Library 13-20.

        :return: Scan request frame.
        :rtype: sp.Packet
        """
        base = self.__base()

        # mac
        base[sp.Dot15d4].fcf_ackreq = 0
        base[sp.Dot15d4].fcf_destaddrmode = 0b10
        base[sp.Dot15d4Data].dest_addr = 0xFFFF

        # aps
        base[sp.ZigbeeAppDataPayloadStub].delivery_mode = 0b10

        # zcl
        base[sp.ZigbeeZLLCommissioningCluster].direction = 0

        cmd = sp.ZLLScanRequest()
        cmd.inter_pan_transaction_id = self.ipan_transaction_id.get()
        # ZigBee
        cmd.logical_type = 1
        cmd.rx_on_when_idle = 1
        # ZLL
        cmd.factory_new = 0
        cmd.address_assignment = 1
        cmd.link_initiator = 1

        self.last_pkt = base / cmd
        return self.last_pkt

    def identify_request(self, duration: int = 0xFFFF) -> sp.Packet:
        """Build identify request frame specified by ZigBee Cluster Library 13-22.

        :return: Identify request frame.
        :rtype: sp.Packet
        """
        if not self.__dest_ieee_addr:
            raise ValueError("dest_ieee_addr not set")

        base = self.__base()

        # mac
        base[sp.Dot15d4].fcf_ackreq = 1
        base[sp.Dot15d4].fcf_destaddrmode = 0b11
        base[sp.Dot15d4Data].dest_addr = self.__dest_ieee_addr.get()

        # aps
        base[sp.ZigbeeAppDataPayloadStub].delivery_mode = 0b00

        # zcl
        base[sp.ZigbeeZLLCommissioningCluster].direction = 0

        cmd = sp.ZLLIdentifyRequest()
        cmd.inter_pan_transaction_id = self.ipan_transaction_id.get()
        cmd.identify_duration = duration

        self.last_pkt = base / cmd
        return self.last_pkt

    def reset_request(self) -> sp.Packet:
        """Build reset to factory request frame specified by
        ZigBee Cluster Library 13-23.

        :return: Reset to factory request frame.
        :rtype: sp.Packet
        """
        if not self.__dest_ieee_addr:
            raise ValueError("dest_ieee_addr not set")

        base = self.__base()

        # mac
        base[sp.Dot15d4].fcf_ackreq = 1
        base[sp.Dot15d4].fcf_destaddrmode = 0b11
        base[sp.Dot15d4Data].dest_addr = self.__dest_ieee_addr.get()

        # aps
        base[sp.ZigbeeAppDataPayloadStub].delivery_mode = 0b00

        # zcl
        base[sp.ZigbeeZLLCommissioningCluster].direction = 0

        cmd = sp.ZLLResetToFactoryNewRequest()
        cmd.inter_pan_transaction_id = self.ipan_transaction_id.get()

        self.last_pkt = base / cmd
        return self.last_pkt

    def join_router_request(
        self,
        network: zb_e.Network,
        nwk_addr: zb_e.NwkAddr,
    ) -> sp.Packet:
        """Build join router request frame specified by
        ZigBee Cluster Library 13-26.

        :return: Join router request frame.
        :rtype: sp.Packet
        """
        if not self.__dest_ieee_addr:
            raise ValueError("dest_ieee_addr not set")
        if not self.__response_id:
            raise ValueError("response_id not set")

        base = self.__base()

        # mac
        base[sp.Dot15d4].fcf_ackreq = 1
        base[sp.Dot15d4].fcf_destaddrmode = 0b11
        base[sp.Dot15d4Data].dest_addr = self.__dest_ieee_addr.get()

        # aps
        base[sp.ZigbeeAppDataPayloadStub].delivery_mode = 0b00

        # zcl
        base[sp.ZigbeeZLLCommissioningCluster].direction = 0

        cmd = sp.ZLLNetworkJoinRouterRequest()
        cmd.inter_pan_transaction_id = self.ipan_transaction_id.get()
        cmd.pan_id_ext = network.ext_pan_id.get()

        cmd.encrypted_network_key = int.from_bytes(
            zbt_c.encrypt_nwk_key(
                self.ipan_transaction_id.get(),
                self.__response_id,
                config.get("keys.touchlink.master").get(),
                network.key.get(),
            ),
            "big",
        )

        cmd.channel = network.channel.get()
        cmd.pan_id = network.pan_id.get()
        cmd.network_address = nwk_addr.get()

        self.last_pkt = base / cmd
        return self.last_pkt
