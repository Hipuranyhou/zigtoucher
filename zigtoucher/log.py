import logging
import termcolor

import zigtoucher.config as config


_DATE_FMT: str = "%Y-%m-%d %H:%M:%S"
_FORMATTER_FMT: str = "[%(asctime)s][%(levelname)7s] %(mod_name)s: %(message)s"


class _ColorFormatter(logging.Formatter):
    """Custom formatter for colored logs in console."""

    fmt = _FORMATTER_FMT

    def format(self, record):
        color_fmt = {
            logging.DEBUG: termcolor.colored(f"{self.fmt}", attrs=["dark"]),
            logging.INFO: termcolor.colored(f"{self.fmt}", color="blue"),
            logging.WARNING: termcolor.colored(f"{self.fmt}", color="yellow"),
            logging.ERROR: termcolor.colored(f"{self.fmt}", color="red"),
            logging.CRITICAL: termcolor.colored(
                f"{self.fmt}", color="red", attrs=["bold"]
            ),
        }
        return logging.Formatter(color_fmt[record.levelno], _DATE_FMT).format(record)


class _FileFormatter(logging.Formatter):
    """Custom formatter for uncolored logs in files."""

    fmt = _FORMATTER_FMT

    def format(self, record):
        return logging.Formatter(self.fmt, _DATE_FMT).format(record)


class _ModNameFilter(logging.Filter):
    """Custom filter to use the last logger name."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.mod_name = record.name.rsplit(".", 1)[-1]
        return True


def config_parse_init() -> None:
    """Setup colored console and scapy-radio logs."""

    logger = logging.getLogger("zigtoucher")
    logger.setLevel(logging.DEBUG)

    # colored stdout log
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.addFilter(_ModNameFilter())
    ch.setFormatter(_ColorFormatter())
    logger.addHandler(ch)

    # colors of gnuradio
    grlogger = logging.getLogger("scapy.gnuradio")
    grlogger.propagate = False
    grlogger.handlers.clear()
    grlogger.addHandler(ch)


def init() -> None:
    """Enable file logger if needed and set logger priority."""

    logger = logging.getLogger("zigtoucher")

    logfile = config.get("log.file")
    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        fh.addFilter(_ModNameFilter())
        fh.setFormatter(_FileFormatter())
        logging.getLogger("zigtoucher.log").info(f"also writing to {logfile}")
        logger.addHandler(fh)

    if not config.get("log.verbose"):
        logger.setLevel(logging.INFO)
        for handler in logger.handlers:
            handler.setLevel(logging.INFO)
