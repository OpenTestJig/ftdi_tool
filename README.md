# ftdi_tool
Stand-alone python3 script that can be used to configure attached FTDI USB2UART converters.

Author: Jan Simons
License: GPLv3+

Depends on [libftdi] (with python bindings)


Note:
- Still WIP
- This script rewrites the internal eeprom of the FTDI chip and may cause the
  device to loose some or all of its previous contents. So it's advised to
  make a backup of the read out eeprom first.


[libftdi]: https://github.com/lipro/libftdi
