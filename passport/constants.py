from passport.util import *

kIDBoot1 = bytes.fromhex(
    "8E E9 B7"
    "8E F7 B7"
    "A9 01"
    "8D F8 B7"
    "8D EA B7"
    "AD E0 B7"
    "8D E1 B7"
    "A9 02"
    "8D EC B7"
    "A9 04"
    "8D ED B7"
    "AC E7 B7"
    "88"
    "8C F1 B7"
    "A9 01"
    "8D F4 B7"
    "8A"
    "4A"
    "4A"
    "4A"
    "4A"
    "AA"
    "A9 00"
    "9D F8 04"
    "9D 78 04")

kIDMaster = bytes.fromhex(
    "8E E9 37"
    "8E F7 37"
    "A9 01"
    "8D F8 37"
    "8D EA 37"
    "AD E0 37"
    "8D E1 37"
    "A9 02"
    "8D EC 37"
    "A9 04"
    "8D ED 37"
    "AC E7 37"
    "88"
    "8C F1 37"
    "A9 01"
    "8D F4 37"
    "8A"
    "4A"
    "4A"
    "4A"
    "4A"
    "AA"
    "A9 00"
    "9D F8 04"
    "9D 78 04")

kIDRWTS = bytes.fromhex(
    "84 48"
    "85 49"
    "A0 02"
    "8C" + find.WILDSTR + find.WILDSTR + \
    "A0 04"
    "8C" + find.WILDSTR + find.WILDSTR + \
    "A0 01"
    "B1 48"
    "AA"
    "A0 0F"
    "D1 48"
    "F0 1B"
    "8A"
    "48"
    "B1 48"
    "AA"
    "68"
    "48"
    "91 48"
    "BD 8E C0"
    "A0 08"
    "BD 8C C0"
    "DD 8C C0"
    "D0 F6"
    "88"
    "D0 F8"
    "68"
    "AA"
    "BD 8E C0"
    "BD 8C C0"
    "A0 08"
    "BD 8C C0"
    "48")

kIDDiversiDOSBootloader = bytes.fromhex("B3 A3 A0 D2 CF D2 D2 C5 8D 87 8D")

kIDProDOSBootloader = bytes.fromhex(
    "01"
    "38"    # SEC
    "B0 03" # BCS +3
    "4C")   # JMP

kIDPascalBootloader1 = bytes.fromhex(
    "01"
    "E0 60" # CPX #$60
    "F0 03" # BEQ +3
    "4C" + find.WILDSTR + "08") # JMP $08**

kIDPascalBootloader2 = bytes.fromhex(
    "01"
    "E0 70" # CPX #$70
    "B0 04" # BCS +4
    "E0 40" # CPX #$40
    "B0")   # BCS

kIDDavidDOS1 = bytes.fromhex(
    "A5 27"
    "C9 09"
    "D0 17")

kIDDavidDOS2 = bytes.fromhex(
    "A2" + find.WILDSTR + \
    "BD" + find.WILDSTR + " 08" + \
    "9D" + find.WILDSTR + " 04" + \
    "CA"
    "10 F7")

kIDDatasoft = bytes.fromhex(
    "01 4C 7E 08 04 8A 0C B8"
    "00 56 10 7A 00 00 1A 16"
    "12 0E 0A 06 53 18 9A 02"
    "10 1B 02 10 4D 56 15 0B"
    "BF 14 14 54 54 54 92 81"
    "1B 10 10 41 06 73 0A 10"
    "33 4E 00 73 12 10 33 7C"
    "00 11 20 E3 49 50 73 1A"
    "10 41 00 23 80 5B 0A 10"
    "0B 4E 9D 0A 10 9D 0C 10"
    "60 1E 53 10 90 53 BC 90"
    "53 00 90 D8 52 00 D8 7C"
    "00 53 80 0B 06 41 00 09"
    "04 45 0C 63 04 90 94 D0"
    "D4 23 04 91 A1 EB CD 06"
    "95 A1 E1 98 97 86")

kIDMicrograms1 = bytes.fromhex(
    "A5 27"
    "C9 09"
    "D0 12"
    "A9 C6"
    "85 3F")

kIDMicrograms2 = bytes.fromhex("4C 00")

kIDQuickDOS = bytes.fromhex(
    "A5 27"
    "C9 09"
    "D0 27"
    "78"
    "AD 83 C0")

kIDRDOS = bytes.fromhex(
    "01"
    "A9 60"
    "8D 01 08"
    "A2 00"
    "A0 1F"
    "B9 00 08"
    "49")

kIDDOS33a = bytes.fromhex(
    "01"
    "A5 27"
    "C9 09"
    "D0 18"
    "A5 2B"
    "4A"
    "4A"
    "4A"
    "4A"
    "09 C0"
    "85 3F"
    "A9 5C"
    "85 3E"
    "18"
    "AD FE 08"
    "6D FF 08" + \
    find.WILDSTR + find.WILDSTR + find.WILDSTR + \
    "AE FF 08"
    "30 15"
    "BD 4D 08"
    "85 3D"
    "CE FF 08"
    "AD FE 08"
    "85 27"
    "CE FE 08"
    "A6 2B"
    "6C 3E 00"
    "EE FE 08"
    "EE FE 08")
