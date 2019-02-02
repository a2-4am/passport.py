from passport.util import *

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
