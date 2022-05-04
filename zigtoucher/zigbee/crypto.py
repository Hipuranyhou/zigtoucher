# Copyright (c) 2009, Joshua Wright <jwright@willhackforsushi.com>
# Updates   (c) 2011-13, Ryan Speers <ryan@rmspeers.com>
#                        & Ricky Melgares <melgares@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#     1. Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#
#     3. Neither the names of the above authors nor the names of contributors
#        may be used to endorse or promote products derived from this software
#        without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import logging
import zigbee_crypt

import scapy.all as sp


logger = logging.getLogger("zigtoucher.zigbee.crypto")


__DOT154_CRYPT_NONE = 0x00  #: No encryption, no MIC
__DOT154_CRYPT_MIC32 = 0x01  #: No encryption, 32-bit MIC
__DOT154_CRYPT_MIC64 = 0x02  #: No encryption, 64-bit MIC
__DOT154_CRYPT_MIC128 = 0x03  #: No encryption, 128-bit MIC
__DOT154_CRYPT_ENC = 0x04  #: Encryption, no MIC
__DOT154_CRYPT_ENC_MIC32 = 0x05  #: Encryption, 32-bit MIC
__DOT154_CRYPT_ENC_MIC64 = 0x06  #: Encryption, 64-bit MIC
__DOT154_CRYPT_ENC_MIC128 = 0x07  #: Encryption, 128-bit MIC


def getmiclen(seclevel: int) -> int:
    """Returns the MIC length in bytes for the specified packet security level"""
    lengths = {
        __DOT154_CRYPT_NONE: 0,
        __DOT154_CRYPT_MIC32: 4,
        __DOT154_CRYPT_MIC64: 8,
        __DOT154_CRYPT_MIC128: 16,
        __DOT154_CRYPT_ENC: 0,
        __DOT154_CRYPT_ENC_MIC32: 4,
        __DOT154_CRYPT_ENC_MIC64: 8,
        __DOT154_CRYPT_ENC_MIC128: 16,
    }

    return lengths[seclevel]


def decrypt(
    source_pkt: sp.Packet,
    key: bytes,
) -> sp.Packet:
    """Decrypt ZigBee frames using AES CCM* with 32-bit MIC"""
    if not sp.ZigbeeSecurityHeader in source_pkt:
        logger.error("decrypt: frame missing ZigbeeSecurityHeader")
        return None
    if not sp.ZigbeeNWK in source_pkt:
        logger.error("decrypt: frame missing ZigbeeNWK")
        return None

    # This function destroys the packet, therefore work on a copy - @cutaway
    pkt: sp.Gen = source_pkt.copy()

    # DOT154_CRYPT_ENC_MIC32 is always used regardless of what is claimed in OTA packet, so we will force it here.
    # This is done because the value of nwk_seclevel in the sp.ZigbeeSecurityHeader does
    # not have to be accurate in the transmitted frame: the Zigbee NWK standard states that
    # the nwk_seclevel should be overwritten in the received frame with the value that is being
    # used by all nodes in the Zigbee network - this is to ensure that unencrypted frames can't be
    # maliciously injected.  i.e. the receiver shouldn't trust the received nwk_seclevel.
    # Recreate 'pkt' by rebuilding the raw data and mic to match:
    pkt.nwk_seclevel = __DOT154_CRYPT_ENC_MIC32
    pkt.data += pkt.mic
    pkt.mic = pkt.data[-4:]
    pkt.data = pkt.data[:-4]

    encrypted: bytes = pkt.data
    # So calculate an amount to crop, equal to the size of the encrypted data and mic.  Note that
    # if there was an FCS, scapy will have already stripped it, so it will not returned by the
    # do_build() call below (and hence doesn't need to be taken into account in crop_size).
    crop_size: int = len(pkt.mic) + len(pkt.data)

    # create NONCE (for crypt) and zigbeeData (for MIC) according to packet type
    sec_ctrl_byte = bytes(pkt[sp.ZigbeeSecurityHeader])[0:1]
    if sp.ZigbeeAppDataPayload in pkt:
        nonce: bytes = (
            struct.pack("L", source_pkt[sp.ZigbeeNWK].ext_src)
            + struct.pack("I", source_pkt[sp.ZigbeeSecurityHeader].fc)
            + sec_ctrl_byte
        )
        zigbeeData = pkt[sp.ZigbeeAppDataPayload].do_build()
    else:
        nonce: bytes = (
            struct.pack("L", source_pkt[sp.ZigbeeSecurityHeader].source)
            + struct.pack("I", source_pkt[sp.ZigbeeSecurityHeader].fc)
            + sec_ctrl_byte
        )
        zigbeeData = pkt[sp.ZigbeeNWK].do_build()
    # For zigbeeData, we need the entire zigbee packet, minus the encrypted data and mic (4 bytes).
    zigbeeData = zigbeeData[:-crop_size]

    (payload, micCheck) = zigbee_crypt.decrypt_ccm(
        key, nonce, pkt.mic, encrypted, zigbeeData
    )

    frametype = pkt[sp.ZigbeeNWK].frametype
    if frametype == 0 and micCheck == 1:
        payload = sp.ZigbeeAppDataPayload(payload)
    elif frametype == 1 and micCheck == 1:
        payload = sp.ZigbeeNWKCommandPayload(payload)
    else:
        payload = sp.Raw(payload)

    # remove old encrypted payload
    source_pkt.data = ""
    source_pkt.mic = ""

    # we do a little change here and return the packet stripped of security
    result = source_pkt / payload
    decrypted_payload = result[sp.ZigbeeSecurityHeader].payload
    # reset security fields and reinsert payload
    result.fcs = None
    if (
        source_pkt.haslayer(sp.ZigbeeAppDataPayload)
        and source_pkt[sp.ZigbeeAppDataPayload].frame_control.security
    ):
        result[sp.ZigbeeAppDataPayload].frame_control.security = 0
        result[sp.ZigbeeAppDataPayload].remove_payload()
        result[sp.ZigbeeAppDataPayload].payload = decrypted_payload
    elif source_pkt[sp.ZigbeeNWK].flags.security:
        result[sp.ZigbeeNWK].flags.security = 0
        result[sp.ZigbeeNWK].remove_payload()
        result[sp.ZigbeeNWK].payload = decrypted_payload
    else:
        return result

    return sp.Dot15d4FCS(result.build())


def encrypt(
    source_pkt: sp.Packet,
    key: bytes,
) -> sp.Packet:
    """Encrypt ZigBee frames using AES CCM* with 32-bit MIC"""
    if not sp.ZigbeeSecurityHeader in source_pkt:
        logger.error("decrypt: frame missing ZigbeeSecurityHeader")
        return None
    if not sp.ZigbeeNWK in source_pkt:
        logger.error("decrypt: frame missing ZigbeeNWK")
        return None

    # remove unencrypted payload
    data = source_pkt[sp.ZigbeeSecurityHeader].payload
    source_pkt[sp.ZigbeeSecurityHeader].remove_payload()

    # This function destroys the packet, therefore work on a copy - @cutaway
    pkt = source_pkt.copy()

    # DOT154_CRYPT_ENC_MIC32 is always used regardless of what is claimed in OTA packet, so we will force it here.
    # This is done because the value of nwk_seclevel in the sp.ZigbeeSecurityHeader does
    # not have to be accurate in the transmitted frame: the Zigbee NWK standard states that
    # the nwk_seclevel should be overwritten in the received frame with the value that is being
    # used by all nodes in the Zigbee network - this is to ensure that unencrypted frames can't be
    # maliciously injected.  i.e. the receiver shouldn't trust the received nwk_seclevel.
    pkt.nwk_seclevel = __DOT154_CRYPT_ENC_MIC32

    # clear data and mic as we are about to create them
    pkt.data = ""
    pkt.mic = ""

    if isinstance(data, sp.Packet):
        decrypted: bytes = data.do_build()
    else:
        decrypted = data

    # create NONCE (for crypt) and zigbeeData (for MIC) according to packet type
    sec_ctrl_byte = bytes(pkt[sp.ZigbeeSecurityHeader])[0:1]
    if sp.ZigbeeAppDataPayload in pkt:
        nonce = (
            struct.pack("L", source_pkt[sp.ZigbeeNWK].ext_src)
            + struct.pack("I", source_pkt[sp.ZigbeeSecurityHeader].fc)
            + sec_ctrl_byte
        )
        zigbeeData: bytes = pkt[sp.ZigbeeAppDataPayload].do_build()
    else:
        nonce = (
            struct.pack("L", source_pkt[sp.ZigbeeSecurityHeader].source)
            + struct.pack("I", source_pkt[sp.ZigbeeSecurityHeader].fc)
            + sec_ctrl_byte
        )
        zigbeeData = pkt[sp.ZigbeeNWK].do_build()

    # minimum security level is DOT154_CRYPT_ENC_MIC32 but provide more if requested
    miclen = getmiclen(source_pkt.nwk_seclevel)
    if miclen < 4:
        miclen = 4

    (payload, mic) = zigbee_crypt.encrypt_ccm(key, nonce, miclen, decrypted, zigbeeData)

    # According to comments in
    # e.g. https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-zbee-security.c
    # nwk_seclevel is not used any more but
    # we should reconstruct and return what was asked for anyway.
    pkt.data = payload + mic
    pkt.nwk_seclevel = source_pkt.nwk_seclevel
    ota_miclen = getmiclen(pkt.nwk_seclevel)
    if ota_miclen > 0:
        pkt.mic = pkt.data[-ota_miclen:]
        pkt.data = pkt.data[:-ota_miclen]

    return pkt
