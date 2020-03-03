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
    print('Usage:   >python.exe decrypt.py input_file output_file')


def decrypt(input_file_name, output_file_name):
    input_file = open(input_file_name, 'rb')
    output_file = open(output_file_name, 'wb')
    print('\nDecrypt from %s to %s' % (input_file_name, output_file_name))
    datContents = dat.readDat(input_file)
    crypterName, data = fdat.decryptFdat(datContents.firmwareData)
    print(' Used crypter', crypterName)
    shutil.copyfileobj(data, output_file)
    print('\nDecrypted to file', output_file_name, 'size', os.stat(output_file_name).st_size)
    print('-----------------------------------------------')

    return {
    'normalUsbDescriptors': datContents.normalUsbDescriptors,
    'updaterUsbDescriptors': datContents.updaterUsbDescriptors,
    'isLens': datContents.isLens,
    'crypterName': crypterName,
    }


def main():
  try:
    decrypt(sys.argv[1], sys.argv[2])
  except:
    print_usage()


if __name__ == '__main__':
 main()
