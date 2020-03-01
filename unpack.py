#https://bufferoverflows.net/exploring-pe-files-with-python/
import pefile

#file = "d:\\Your files\\Sanin\\Downloads\\Update_ILCE7M3V310.exe"
#file = "Update_ILCE7M3V310.exe"
#pe = pefile.PE(file)
#pe.print_info()  # Prints all Headers in a human readable format

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
    print('Usage:   >unpack.py firmware_exe_file output_dir')


def unpack(exe_file_name='Update_ILCE7M3V310.exe', out_dir='ILCE7M3V310'):
    """Extract the exe file to the specified directory"""
    exe_file = open(exe_file_name, 'rb')
    #os.mkdir(out_dir)
    print('\nUnpacking file %s to folder %s' % (exe_file.name, out_dir))
    exe_file_mtime = os.stat(exe_file.name).st_mtime
    exe_file_size = os.stat(exe_file.name).st_size
    print('\nFile %s size %d' % (exe_file.name, exe_file_size))

    datConf = None
    fdatConf = None

    if pe.isExe(exe_file):
        with open(out_dir + '/firmware.dat', 'w+b') as datFile, open(out_dir + '/firmware.fdat', 'w+b') as fdatFile:
            mtime = unpack_exe(exe_file, datFile)
            datConf = unpack_dat(datFile, fdatFile)
            fdatConf = unpack_fdat(fdatFile, out_dir, mtime)
    else:
        raise Exception('Unknown file type!')

    with open(out_dir + '/config.yaml', 'w') as yamlFile:
        writeYaml({'dat': datConf, 'fdat': fdatConf}, yamlFile)


def unpack_exe(exeFile, datFile):
    print('\n-----------------------------------------------')
    print('From %s extracting firmware to %s ' % (exeFile.name, datFile.name))
    exeSectors = pe.readExe(exeFile)
    print('\nEXE file sections:')
    print('-----------------------------------------------')
    print(' name      offset     size')
    print('-----------------------------------------------')
    for key in exeSectors.keys():
        print('%-10s %-10d %-10d' % (key, exeSectors[key].offset, exeSectors[key].size))
    zipFile = exeSectors['_winzip_']
    zippedFiles = dict((file.path, file) for file in zip.readZip(zipFile))
    print('\nFiles in "_winzip_" section:')
    for key in zippedFiles.keys():
        print(key)

    datFileName = dat.findDat(zippedFiles.keys())
    zippedDatFile = zippedFiles[datFileName]
    shutil.copyfileobj(zippedDatFile.contents, datFile)
    print('\nExtracted dat file ', datFileName, 'to', datFile.name)
    print('-----------------------------------------------')

    ###print('mtime=', zippedDatFile.mtime)
    return zippedDatFile.mtime

def unpack_dat(datFile, fdatFile):
    print('\nExtract and decrypt FDAT section from %s to %s'%(datFile.name, fdatFile.name))
    datContents = dat.readDat(datFile)
    crypterName, data = fdat.decryptFdat(datContents.firmwareData)
    print(' Used crypter', crypterName)
    shutil.copyfileobj(data, fdatFile)
    print('\nExtracted fdat file', fdatFile.name, 'size', os.stat(fdatFile.name).st_size)
    print('-----------------------------------------------')

    return {
    'normalUsbDescriptors': datContents.normalUsbDescriptors,
    'updaterUsbDescriptors': datContents.updaterUsbDescriptors,
    'isLens': datContents.isLens,
    'crypterName': crypterName,
    }

def unpack_fdat(fdatFile, outDir, mtime):
    print('\nunpack_fdat from %s to folder %s %s'%(fdatFile.name, outDir, str(mtime)))
    fdatContents = fdat.readFdat(fdatFile)

    writeFileTree([
        toUnixFile('/firmware.tar', fdatContents.firmware, mtime),
        toUnixFile('/updater.img', fdatContents.fs, mtime),
        ], outDir)

    return {
        'model': fdatContents.model,
        'region': fdatContents.region,
        'version': fdatContents.version,
        'isAccessory': fdatContents.isAccessory,
         }


def main():
  try:
    unpack(sys.argv[1], sys.argv[2])
  except:
    print_usage()


if __name__ == '__main__':
 main()
