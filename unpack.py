from collections import OrderedDict
import io
import os
import shutil
from stat import *
import sys
import yaml

from fwtool import archive, pe, zip
from fwtool.sony import backup, bootloader, dat, fdat, flash, wbi


def print_usage():
    print('unpack.py firmware_exe_file output_dir')


def main():
  try:
    unpackCommand(args.inFile, args.outDir)
  except:
    print_usage()


if __name__ == '__main__':
 main()
