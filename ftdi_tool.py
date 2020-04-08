#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: fdm=indent foldlevel=0 foldnestmax=1 expandtab tabstop=4 shiftwidth=4 softtabstop=4
# kate: replace-tabs on; indent-width 4; indent-mode python;

"""
Stand-alone script that can be used to configure attached FTDI USB2UART converters.

 Author: Jan Simons
 License: GPLv3+
 (c) 2019-2020

 Note:
  - based on libftdi python examples complete.py and simple.py
  - still WIP
"""

import argparse
import logging
import sys

logging.basicConfig(format='[%(levelname)-8s]  %(message)s')
log = logging.getLogger(__name__)


try:
    import ftdi1 as ftdi
except ImportError:
    log.critical("Cannot find libftdi python bindings!")
    sys.exit(1)


PROGVER = "v1.1.0"


class FtdiException(Exception):
    """specialised exception that will be thrown by this module"""
    pass


VENDOR_ID = 0x0403  # FTDI vendor id
FLAGMAP = {
    "RXD": ftdi.INVERT_RXD,
    "TXD": ftdi.INVERT_TXD,
    "RTS": ftdi.INVERT_RTS,
    "CTS": ftdi.INVERT_CTS,
    "DTR": ftdi.INVERT_DTR,
    "DSR": ftdi.INVERT_DSR,
    "DCD": ftdi.INVERT_DCD,
    "RI": ftdi.INVERT_RI,
    }


def decode_flags(value):
    """Decode the binary/integer representation of the flags"""
    ret = ""
    for token, bit in FLAGMAP.items():
        if value & bit:
            ret += token + "- "
        else:
            ret += token + "+ "
    return ret


def output(message, noprefix=False):
    """write message to the screen"""
    if noprefix:
        print("{:s}".format(message))
    else:
        print("[   ] {:s}".format(message))


class FtdiContext(object):
    """Helper class to handle an FTDI context"""
    def __init__(self):
        self.context = ftdi.new()
        if self.context == 0:
            raise FtdiException("Could not open FTDI context.")

    def __enter__(self):
        return self.context

    def __exit__(self, exeptype, value, traceback):
        ftdi.free(self.context)

    def call(self, function, *fargs):
        """Call a libftdi function and log its output."""
        values = None
        log.debug("calling ftdi_%s with args: (context, %s)",
                  function.__name__, list(fargs))
        ret = function(self.context, *fargs)
        log.debug("got return value(s): %s", ret)
        if isinstance(ret, (list, tuple)) and len(ret) > 1:
            values = ret[1:]
            if isinstance(values, (list, tuple)) and len(values) == 1:
                values = values[0]
            ret = ret[0]
        else:
            # just return the return code
            values = ret
        if ret < 0:
            raise FtdiException(
                "{} failed: {:d} ({})".format(
                    function.__name__,
                    ret,
                    ftdi.get_error_string(self.context)))
        else:
            log.debug("returning: %s", values)
            return values


def check_libversion(myargs):
    """Check context and library version"""
    version_info = ftdi.get_library_version()
    if myargs.verbose:
        log.info(
            "FTDI version: %d.%d.%d (version_str: %s, snapshot_str: %s)",
            version_info.major, version_info.minor, version_info.micro,
            version_info.version_str, version_info.snapshot_str)


def list_devices(myargs):
    """list FTDI devices"""
    # TODO: find all FTDI devices
    # "lsusb | grep "0403:""

    # try to open any ftdi device with specified device id
    devlist = myargs.ctx.call(ftdi.usb_find_all, VENDOR_ID, myargs.deviceid)
    if devlist is None:
        raise FtdiException(
            "Could not find any matching FTDI device for product id "
            "{:04x}.".format(myargs.deviceid))

    curnode = devlist
    i = 0
    while curnode is not None:
        try:
            manufacturer, description, serial = myargs.ctx.call(
                ftdi.usb_get_strings2, curnode.dev)
            output(
                '#{:d}: manufacturer="{:s}" description="{:s}" serial="{:s}"'.format(
                    i, manufacturer, description, serial))
        except FtdiException as exc:
            log.error(str(exc))
        curnode = curnode.next
        i += 1


def read_eeprom(myargs):
    """read out eeprom contents"""
    eeprom_val = myargs.ctx.call(ftdi.read_eeprom_location, myargs.eepromaddress)
    output("eeprom @ {:d}: 0x{:04x}".format(myargs.eepromaddress, eeprom_val))
    output("eeprom:")
    myargs.ctx.call(ftdi.read_eeprom)
    size = myargs.ctx.call(ftdi.get_eeprom_value, ftdi.CHIP_SIZE)
    eeprom = myargs.ctx.call(ftdi.get_eeprom_buf, size)
    outline = ""
    for i in range(size):
        octet = eeprom[i]
        if sys.version_info[0] < 3:  # python 2
            octet = ord(octet)
        outline += "{:02x} ".format(octet)
        if (i+1) % myargs.bytesperline == 0:
            output(outline, noprefix=True)
            outline = ""
    # show EEPROM contents
    myargs.ctx.call(ftdi.eeprom_decode, 1)


def init_eeprom(myargs):
    """initialise the eeprom with default values"""
    eeprom_val = myargs.ctx.call(ftdi.read_eeprom_location, myargs.eepromaddress)
    output("eeprom @ {:d}: 0x{:04x}".format(myargs.eepromaddress, eeprom_val))
    myargs.ctx.call(ftdi.read_eeprom)
    size = myargs.ctx.call(ftdi.get_eeprom_value, ftdi.CHIP_SIZE)

    myargs.ctx.call(ftdi.eeprom_initdefaults,
                    "FTDI",
                    "USB HS Serial Converter",
                    "FT000001")
    size_check = myargs.ctx.call(ftdi.eeprom_build)

    size = myargs.ctx.call(ftdi.get_eeprom_value, ftdi.CHIP_SIZE)
    output("writing eeprom ({} bytes into eeprom of size {})".format(size_check, size))
    myargs.ctx.call(ftdi.write_eeprom)
    output("Powercycle the device to apply changes.")


def erase_eeprom(myargs):
    """erase the eeprom"""
    log.warning("Erasing eeprom. This will set the device and vendor id to 0x0000!")

    # erase eeprom
    myargs.ctx.call(ftdi.erase_eeprom)
    output("Powercycle the device to apply changes.")


def set_flag(myargs):
    """set or clear an invert flag in the eeprom"""
    eeprom_val = myargs.ctx.call(ftdi.read_eeprom_location, myargs.eepromaddress)
    output("eeprom @ {:d}: 0x{:04x}".format(myargs.eepromaddress, eeprom_val))
    myargs.ctx.call(ftdi.read_eeprom)
    myargs.ctx.call(ftdi.eeprom_decode, 0)

    size = myargs.ctx.call(ftdi.get_eeprom_value, ftdi.CHIP_SIZE)

    org_value = myargs.ctx.call(ftdi.get_eeprom_value, ftdi.INVERT)

    log.info("orginal flags:    %s", decode_flags(org_value))
    value = org_value

    # set INVERT_... flags
    for flag in myargs.flags:
        if flag[-1] == "-":
            value |= FLAGMAP[flag[:-1]]
        else:
            value &= ~FLAGMAP[flag[:-1]]
    log.info("new flags:        %s", decode_flags(value))

    if value == org_value:
        output("No change needed (old flags are already OK).")
        output("unmodified flags: %s", decode_flags(org_value))
        return

    myargs.ctx.call(ftdi.set_eeprom_value, ftdi.INVERT, value)
    rb_value = myargs.ctx.call(ftdi.get_eeprom_value, ftdi.INVERT)

    log.info("read back flags:  %s", decode_flags(rb_value))

    if rb_value != value:
        raise FtdiException(
            "Read back value for flags is not as expected! Cannot write eeprom.")

    myargs.ctx.call(ftdi.set_eeprom_value, ftdi.VENDOR_ID, VENDOR_ID)
    myargs.ctx.call(ftdi.set_eeprom_value, ftdi.PRODUCT_ID, myargs.deviceid)

    size_check = myargs.ctx.call(ftdi.eeprom_build)
    size = myargs.ctx.call(ftdi.get_eeprom_value, ftdi.CHIP_SIZE)
    output("writing eeprom ({} bytes into eeprom of size {})".format(size_check, size))
    myargs.ctx.call(ftdi.write_eeprom)
    output("Powercycle the device to apply changes.")


def read_chipid(myargs):
    """read the chip id"""
    ret, chipid = ftdi.read_chipid(myargs.ctx)
    if ret == 0:
        output("chip id: {:x}".format(chipid))


def parse_args():
    """Argument parsing"""

    def auto_int(xin):
        """Helper to automatically cast to int"""
        return int(xin, 0)

    parser = argparse.ArgumentParser(
        prog=sys.argv[0],
        description="Utility to configure a FTDI USB2Serial converter")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s " + PROGVER)
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="be verbose")
    parser.add_argument("-d", "--deviceid", type=auto_int, default=0x6015,
                        help="device id to work on (default: 0x6015)")
    parser.add_argument("-e", "--eepromaddress", type=auto_int, default=1,
                        help="address of the eeprom (default: 1)")

    # setup sub commands:
    subparsers = parser.add_subparsers(help="allowed sub-commands:", dest='subparser_name')

    # - list
    parser_list = subparsers.add_parser("list", help="list FTDI devices")
    parser_list.set_defaults(func=list_devices)

    # - set
    parser_set = subparsers.add_parser("set",
                                       formatter_class=argparse.RawTextHelpFormatter,
                                       help="set FTDI attributes")
    parser_set.set_defaults(func=set_flag)
    parser_set.add_argument(
        "flags",
        nargs="+",
        type=str.upper,
        help=(
            "Flags to set.\n"
            "By default all flags are set to the + variant\n"
            "   (+ --> active low,  internal pullup,   0=high, 1=low)\n"
            "   (- --> active high, internal pulldown, 1=high, 0=low)"),
        choices=(
            "TXD+", "TXD-",
            "RXD+", "RXD-",
            "RTS+", "RTS-",
            "CTS+", "CTS-",
            "DTR+", "DTR-",
            "DSR+", "DSR-",
            "DCD+", "DCD-",
            "RI+", "RI-",
            ),
        )

    # - chipid
    parser_chipid = subparsers.add_parser("chipid", help="read chip ID")
    parser_chipid.set_defaults(func=read_chipid)

    # - eeprom
    parser_rdeeprom = subparsers.add_parser("eeprom", help="read eeprom")
    parser_rdeeprom.add_argument("-b", "--bytesperline", default=32, type=int,
                                 choices=(8, 16, 24, 32, 40, 48, 64, 128, 256, 512, 1024),
                                 help="the number of bytes per line to be printed")
    parser_rdeeprom.set_defaults(func=read_eeprom)

    # - erase
    parser_clreeprom = subparsers.add_parser("erase",
                                             help="erase all eeprom contents")
    parser_clreeprom.set_defaults(func=erase_eeprom)

    # - initeeprom
    parser_initeeprom = subparsers.add_parser("initeeprom",
                                              help="init eeprom with default contents")
    parser_initeeprom.set_defaults(func=init_eeprom)

    # - recover
    parser_recover = subparsers.add_parser("recover",
                                           help="try to recover a device with erased chip ID")
    parser_recover.set_defaults(func=init_eeprom)

    if len(sys.argv) <= 1:
        parser.print_help()
        return None
    return parser.parse_args()


if __name__ == "__main__":
    argsp = parse_args()
    if argsp is not None:
        # set verbosity
        log.setLevel(30 - argsp.verbose * 10)

        try:
            # initialise
            with FtdiContext() as ctx:
                argsp.ctx = ctx
                check_libversion(argsp)

                # open usb
                if argsp.subparser_name == "recover":
                    ctx.call(ftdi.usb_open, 0x0000, 0x0000)
                elif argsp.subparser_name != "list":
                    ctx.call(ftdi.usb_open, VENDOR_ID, argsp.deviceid)
                    log.info("opened ftdi usb device.")

                # call corresponding function
                if argsp.subparser_name is not None:
                    argsp.func(argsp)

                # close usb
                ctx.call(ftdi.usb_close)
                log.info("closed ftdi usb device.")

        except FtdiException as exc:
            log.error(str(exc))
