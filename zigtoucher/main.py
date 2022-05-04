from typing import List
import logging
import sys

import scapy.all as sp

import zigtoucher.cli as cli
import zigtoucher.config as config
import zigtoucher.log as log


def main(args: List[str] = None) -> int:

    # scapy setup
    sp.conf.dot15d4_protocol = "zigbee"
    sp.conf.verb = 0

    # our setup
    log.config_parse_init()
    logger = logging.getLogger("zigtoucher.main")

    try:
        config.parse()
        log.init()
        cli.CLI().cmdloop()
    except Exception as e:
        if config.get("log.verbose"):
            logger.exception("")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
