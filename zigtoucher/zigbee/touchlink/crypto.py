from Crypto.Cipher import AES
import logging


logger = logging.getLogger("zigtoucher.zigbee.lightlink.touchlink.crypto")


def get_development_key(ipan_transaction_id: int, response_id: int) -> bytes:
    return b"PhLi" + ipan_transaction_id + b"CLSN" + response_id


def encrypt_nwk_key(
    ipan_transaction_id: int,
    response_id: int,
    key: bytes,
    nwk_key: bytes,
    development: bool = False,
) -> bytes:
    """Enrypt network key for Touchlink key transport as specified in
    ZigBee Cluster Library 13-56.

    Tested using vectors from ZigBee Cluster Library 13-60.

    :param ipan_transaction_id: Transaction ID.
    :type ipan_transaction_id: int
    :param response_id: Scan response ID.
    :type response_id: int
    :param key: Key used for encryption.
    :type key: bytes
    :param nwk_key: Key to be encrypted.
    :type nwk_key: bytes
    :param development: Should development operation be used, defaults to False
    :type development: bool, optional
    :return: Encrypted network key.
    :rtype: bytes
    """
    # get all inputs as bytes
    transaction_id = ipan_transaction_id.to_bytes(4, "big")
    response_id = response_id.to_bytes(4, "big")
    if not development:
        # A
        expanded = 2 * transaction_id + 2 * response_id
        # B
        transport_crypto = AES.new(key, AES.MODE_ECB)
        transport_key = transport_crypto.encrypt(expanded)
    else:
        transport_key = key
    # C
    nwk_crypto = AES.new(transport_key, AES.MODE_ECB)
    return nwk_crypto.encrypt(nwk_key)


def decrypt_nwk_key(
    ipan_transaction_id: int,
    response_id: int,
    key: bytes,
    nwk_key: bytes,
    development: bool = False,
) -> bytes:
    """Decrypt network key from Touchlink key transport as specified in
    ZigBee Cluster Library 13-56.

    Tested using vectors from ZigBee Cluster Library 13-60.

    :param ipan_transaction_id: Transaction ID.
    :type ipan_transaction_id: int
    :param response_id: Scan response ID.
    :type response_id: int
    :param key: Key used for decryption.
    :type key: bytes
    :param nwk_key: Key to be decrypted.
    :type nwk_key: bytes
    :param development: Should development operation be used, defaults to False
    :type development: bool, optional
    :return: Decrypted network key.
    :rtype: bytes
    """
    # get all inputs as bytes
    transaction_id = ipan_transaction_id.to_bytes(4, "big")
    response_id = response_id.to_bytes(4, "big")
    if not development:
        # D
        expanded = 2 * transaction_id + 2 * response_id
        # E
        transport_crypto = AES.new(key, AES.MODE_ECB)
        transport_key = transport_crypto.encrypt(expanded)
    else:
        transport_key = key
    # F
    nwk_crypto = AES.new(transport_key, AES.MODE_ECB)
    return nwk_crypto.decrypt(nwk_key)
