# Katy
Katy - Wow packet sniffer for (x86, x64 client)

[![Build status](https://ci.appveyor.com/api/projects/status/trp02gu6y6k3diya?svg=true)](https://ci.appveyor.com/project/Konctantin/katy)

# Build instructions
First grab the code using git:

```
git clone https://github.com/Konctantin/Katy.git
cd Katy
git submodule update --init --recursive
```

Use Visual Studio 2015 to build it once you have all dependencies.

#Dump format

```c++
struct MainHeader
{
  char signature[3]; // 'PKT'
  byte version[2]; // 0x01, 0x03
  byte snifferID;
  uint build;
  char language[4]; // Client locale: 'enGB', 'enUS', 'deDE', 'ruRU' and ect.
  byte sessionKey[40]; // all zero
  uint unixTime;
  uint tickCount;
  uint optionalHeaderLength;
};
byte[optionalHeaderLength] optionalData;
```
```c++
struct ChunkHeader
{
  char direction[4]; // 'SMSG', 'CMSG'
  uint sessionID;
  uint tickCount;
  uint optionalDataLength;
  uint dataLength;
};
byte[optionalDataLength] optionalData;
byte[dataLength] data;
```

# Dependencies:
 * https://github.com/TsudaKageyu/minhook