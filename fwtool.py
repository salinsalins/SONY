#!/usr/bin/env python3
"""A command line application to unpack Sony camera firmware images, based on fwtool by oz_paulb / nex-hack"""

from __future__ import print_function
import argparse
from collections import OrderedDict
import io
import os
import shutil
from stat import *
import sys
import yaml

from fwtool import archive, pe, zip
from fwtool.sony import backup, bootloader, dat, fdat, flash, wbi

scriptRoot = getattr(sys, '_MEIPASS', os.path.dirname(__file__))

def patchTar(input='firmware.tar'):
 import tarfile
 def check(targ):
  if not (targ.startswith(b'0,') and
          targ.endswith(b',0011430a,000001a4,00000000,000003e8,root,root,-1,-1,SYSASTRA-DSLR/TI/')):
   raise Exception('Patch rejected')
 tar = tarfile.open(input, 'r')
 name = '0111_backup_sum/backup.sum'
 data = tar.extractfile(name).read()
 pos0 = tar.getmember(name).offset_data
 pos = data.find(b'CX62200_ALLLANG.bin')
 repl = data[pos - 80:pos]
 check(repl)
 pos = data.find(b'CX62200_J1.bin')
 targ = data[pos - 80:pos]
 check(targ)
 datar = data.replace(targ, repl)
 name1 = '0110_backup/SYSASTRA-DSLR/TI/CX62200_ALLLANG.bin'
 data1 = tar.extractfile(name1).read()
 name2 = '0110_backup/SYSASTRA-DSLR/TI/CX62200_J1.bin'
 pos2 = tar.getmember(name2).offset_data
 tar.close()

 f = open(input, "r+b")
 f.seek(pos0)
 f.write(datar)
 f.seek(pos2)
 f.write(data1)
 f.close()



def mkdirs(path):
 try:
  os.makedirs(path)
 except OSError:
  pass

def setmtime(path, time):
 os.utime(path, (time, time))

def writeFileTree(files, path):
 """Writes a list of UnixFiles to the disk, unpacking known archive files"""
 print('\nwriteFileTree', files, path)
 files = [(path + file.path, file) for file in files]

 # Write files:
 for fn, file in files:
  if S_ISDIR(file.mode):
   mkdirs(fn)
  elif S_ISREG(file.mode):
   mkdirs(os.path.dirname(fn))
   with open(fn, 'wb') as dstFile:
    shutil.copyfileobj(file.contents, dstFile)

 # Recursion:
 for fn, file in files:
  if S_ISREG(file.mode):
   with open(fn, 'rb') as dstFile:
    if archive.isArchive(dstFile):
     print('Unpacking %s' % fn)
     writeFileTree(archive.readArchive(dstFile), fn + '_unpacked')

 # Set mtimes:
 for fn, file in files:
  if S_ISDIR(file.mode) or S_ISREG(file.mode):
   setmtime(fn, file.mtime)

def toUnixFile(path, file, mtime=0):
 return archive.UnixFile(
  path = path,
  size = -1,
  mtime = mtime,
  mode = S_IFREG | 0o775,
  uid = 0,
  gid = 0,
  contents = file,
 )

def writeYaml(yamlData, file):
 yaml.add_representer(tuple, lambda dumper, data: dumper.represent_list(data))
 yaml.add_representer(dict, lambda dumper, data: dumper.represent_mapping(dumper.DEFAULT_MAPPING_TAG, data, flow_style=False))
 representInt = lambda dumper, data: dumper.represent_int('0x%X' % data if data >= 10 else data)
 yaml.add_representer(int, representInt)
 try:
  yaml.add_representer(long, representInt)
  yaml.add_representer(unicode, lambda dumper, data: dumper.represent_str(str(data)))
 except NameError:
  # Python 3
  pass
 yaml.dump(yamlData, file)

class OrderedSafeLoader(yaml.SafeLoader):
 def __init__(self, *args, **kwargs):
  yaml.SafeLoader.__init__(self, *args, **kwargs)
  def constructMapping(loader, node):
   loader.flatten_mapping(node)
   return OrderedDict(loader.construct_pairs(node))
  self.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, constructMapping)

def getDevices():
 with open(scriptRoot + '/devices.yml', 'r') as f:
  return yaml.load(f, OrderedSafeLoader)


def unpackInstaller(exeFile, datFile):
 print('\nExtracting installer %s from  %s'%(datFile.name, exeFile.name))
 exeSectors = pe.readExe(exeFile)
 for key in exeSectors.keys():
  print(key)
 print('-----------------------------------------------')
 zipFile = exeSectors['_winzip_']
 zippedFiles = dict((file.path, file) for file in zip.readZip(zipFile))
 print('\nFiles in "_winzip_" section:')
 for key in zippedFiles.keys():
  print(key)
 print('-----------------------------------------------')

 datFileName = dat.findDat(zippedFiles.keys())
 print('dat file name:', datFileName)
 zippedDatFile = zippedFiles[datFileName]
 shutil.copyfileobj(zippedDatFile.contents, datFile)

 ###print('mtime=', zippedDatFile.mtime)
 return zippedDatFile.mtime


def unpackDat(datFile, fdatFile):
 print('\nExtract from %s firmware and decrypt to "%s"'%(datFile.name, fdatFile.name))
 datContents = dat.readDat(datFile)
 crypterName, data = fdat.decryptFdat(datContents.firmwareData)
 shutil.copyfileobj(data, fdatFile)
 print(' Used crypter', crypterName)

 return {
  'normalUsbDescriptors': datContents.normalUsbDescriptors,
  'updaterUsbDescriptors': datContents.updaterUsbDescriptors,
  'isLens': datContents.isLens,
  'crypterName': crypterName,
 }


def unpackFdat(fdatFile, outDir, mtime):
 print('\nunpackFdat from "%s" to "%s" %s'%(fdatFile.name, outDir, str(mtime)))
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


def unpackDump(dumpFile, outDir, mtime):
 print('Extracting partitions')
 writeFileTree((toUnixFile('/nflasha%d' % i, f, mtime) for i, f in flash.readPartitionTable(dumpFile)), outDir)


def unpackBootloader(file, outDir, mtime):
 print('Extracting bootloader partition')
 files = list(bootloader.readBootloader(file))
 writeFileTree((toUnixFile('/' + f.name, f.contents, mtime) for f in files), outDir)
 with open(outDir + '/bootfiles.yaml', 'w') as yamlFile:
  writeYaml([{f.name: {'version': f.version, 'loadaddr': f.loadaddr}} for f in files], yamlFile)


def unpackWbi(file, outDir, mtime):
 print('Extracting warm boot image')
 writeFileTree((toUnixFile('/0x%08x.dat' % c.physicalAddr, c.contents, mtime) for c in wbi.readWbi(file)), outDir)


def unpackCommand(file, outDir):
 """Extracts the input file to the specified directory"""
 mkdirs(outDir)
 print('\nUntacking file "%s" to folder "%s"'%(file.name, outDir))
 mtime = os.stat(file.name).st_mtime

 datConf = None
 fdatConf = None

 if pe.isExe(file):
  with open(outDir + '/firmware.dat', 'w+b') as datFile, open(outDir + '/firmware.fdat', 'w+b') as fdatFile:
   mtime = unpackInstaller(file, datFile)
   datConf = unpackDat(datFile, fdatFile)
   fdatConf = unpackFdat(fdatFile, outDir, mtime)
 elif dat.isDat(file):
  with open(outDir + '/firmware.fdat', 'w+b') as fdatFile:
   datConf = unpackDat(file, fdatFile)
   fdatConf = unpackFdat(fdatFile, outDir, mtime)
 elif fdat.isFdat(file):
  fdatConf = unpackFdat(file, outDir, mtime)
 elif flash.isPartitionTable(file):
  unpackDump(file, outDir, mtime)
 elif bootloader.isBootloader(file):
  unpackBootloader(file, outDir, mtime)
 elif wbi.isWbi(file):
  unpackWbi(file, outDir, mtime)
 else:
  raise Exception('Unknown file type!')

 with open(outDir + '/config.yaml', 'w') as yamlFile:
  writeYaml({'dat': datConf, 'fdat': fdatConf}, yamlFile)


def packCommand(firmwareFile, fsFile, bodyFile, configFile, device, outDir, defaultVersion='9.99'):
 mkdirs(outDir)

 if configFile:
  config = yaml.safe_load(configFile)
  datConf = config['dat']
  fdatConf = config['fdat']
 elif device:
  devices = getDevices()
  if device not in devices:
   raise Exception('Unknown device')
  config = devices[device]

  datConf = {
   'crypterName': 'gen%d' % config['gen'],
   'normalUsbDescriptors': [],
   'updaterUsbDescriptors': [],
   'isLens': False,
  }
  fdatConf = {
   'model': config['model'],
   'region': config['region'] if 'region' in config else 0,
   'version': defaultVersion,
   'isAccessory': False,
  }

 if not fsFile and bodyFile:
  print('Packing updater file system')
  fsFile = open(outDir + '/updater_packed.img', 'w+b')
  archive.cramfs.writeCramfs([toUnixFile('/bodylib/libupdaterbody.so', bodyFile)], fsFile)

 if fdatConf:
  print('Creating firmware image')
  with open(outDir + '/firmware_packed.fdat', 'w+b') as fdatFile:
   fdat.writeFdat(fdat.FdatFile(
    model = fdatConf['model'],
    region = fdatConf['region'],
    version = fdatConf['version'],
    isAccessory = fdatConf['isAccessory'],
    firmware = firmwareFile if firmwareFile else io.BytesIO(),
    fs = fsFile if fsFile else io.BytesIO(),
   ), fdatFile)

   if datConf:
    print('Encrypting firmware image')
    encrypted = fdat.encryptFdat(fdatFile, datConf['crypterName'])
    with open(outDir + '/firmware_packed.dat', 'w+b') as datFile:
     dat.writeDat(dat.DatFile(
      normalUsbDescriptors = datConf['normalUsbDescriptors'],
      updaterUsbDescriptors = datConf['updaterUsbDescriptors'],
      isLens = datConf['isLens'],
      firmwareData = encrypted,
     ), datFile)


def HexDump(data, n=16, indent=0):
 for i in range(0, len(data), n):
  line = bytearray(data[i:i+n])
  hex = ' '.join('%02x' % c for c in line)
  text = ''.join(chr(c) if 0x21 <= c <= 0x7e else '.' for c in line)
  return '%*s%-*s %s' % (indent, '', n*3, hex, text)


def printHexDump(data, n=16, indent=0):
  print(HexDump(data, n, indent))


def printBackupCommand(file):
 """Prints all properties in a Backup.bin file"""
 for property in backup.readBackup(file):
  print('id=0x%08x, size=0x%04x, attr=0x%02x:' % (property.id, len(property.data), property.attr))
  printHexDump(property.data, indent=2)
  if property.resetData and property.resetData != property.data:
   print('reset data:')
   printHexDump(property.resetData, indent=2)
  print('')


def listDevicesCommand():
 for device in getDevices():
  print(device)


def main():
 """Command line main"""
 parser = argparse.ArgumentParser()
 subparsers = parser.add_subparsers(dest='command', title='commands')
 unpack = subparsers.add_parser('unpack', description='Unpack a firmware file')
 unpack.add_argument('-f', dest='inFile', type=argparse.FileType('rb'), required=True, help='input file')
 unpack.add_argument('-o', dest='outDir', required=True, help='output directory')
 pack = subparsers.add_parser('pack', description='Pack a firmware file')
 packConfig = pack.add_mutually_exclusive_group(required=True)
 packConfig.add_argument('-c', dest='configFile', type=argparse.FileType('rb'), help='configuration file (config.yaml)')
 packConfig.add_argument('-d', dest='device', help='device name')
 packBody = pack.add_mutually_exclusive_group()
 packBody.add_argument('-u', dest='updaterFile', type=argparse.FileType('rb'), help='updater file (updater.img)')
 packBody.add_argument('-b', dest='updaterBodyFile', type=argparse.FileType('rb'), help='updater body file (libupdaterbody.so)')
 pack.add_argument('-f', dest='firmwareFile', type=argparse.FileType('rb'), help='firmware file (firmware.tar)')
 pack.add_argument('-o', dest='outDir', required=True, help='output directory')
 printBackup = subparsers.add_parser('print_backup', description='Print the contents of a Backup.bin file')
 printBackup.add_argument('-f', dest='backupFile', type=argparse.FileType('rb'), required=True, help='backup file')
 subparsers.add_parser('list_devices', description='List all known devices')

 #print(os.getcwd())
 #fff = open('c:\\Users\\sanin\\PycharmProjects\\SONY\\ILCE7M3V310\\config.yaml')

 args = parser.parse_args()
 if args.command == 'unpack':
  unpackCommand(args.inFile, args.outDir)
 elif args.command == 'pack':
  packCommand(args.firmwareFile, args.updaterFile, args.updaterBodyFile, args.configFile, args.device, args.outDir)
 elif args.command == 'print_backup':
  printBackupCommand(args.backupFile)
 elif args.command == 'list_devices':
  listDevicesCommand()
 else:
  parser.print_usage()


if __name__ == '__main__':
 main()
