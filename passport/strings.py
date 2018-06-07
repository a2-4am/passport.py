STRINGS = {
    "header":      "Passport.py by 4am (2018-06-06)\n", # max 32 characters
    "reading":     "Reading from {filename}\n",
    "diskrwts":    "Using disk's own RWTS\n",
    "bb00":        "T00,S05 Found $BB00 protection check\n"
                   "T00,S0A might be unreadable\n",
    "sunburst":    "T00,S04 Found Sunburst disk\n"
                   "T11,S0F might be unreadable\n",
    "optimum":     "T00,S00 Found Optimum Resource disk\n"
                   "T01,S0F might be unreadable\n",
    "builtin":     "Using built-in RWTS\n",
    "switch":      "T{track},S{sector} Switching to built-in RWTS\n",
    "writing":     "Writing to {filename}\n",
    "unformat":    "T{track} is unformatted\n",
    "f7":          "T{track} Found $F7F6EFEEAB protection track\n",
    "sync":        "T{track} Found nibble count protection track\n",
    "optbad":      "T{track},S{sector} is unreadable (ignoring)\n",
    "passver":     "Verification complete. The disk is good.\n",
    "passdemuf":   "Demuffin complete.\n",
    "passcrack":   "Crack complete.\n",
    "passcrack0":  "\n"
                   "The disk was copied successfully, but\n"
                   "Passport did not apply any patches.\n\n"
                   "Possible reasons:\n"
                   "- The source disk is not copy protected.\n"
                   "- The target disk works without patches.\n"
                   "- The disk uses an unknown protection,\n"
                   "  and Passport can not help any further.\n",
    "fail":        "\n"
                   "T{track},S{sector} Fatal read error\n\n",
    "fatal0000":   "\n"
                   "Possible reasons:\n"
                   "- The source file does not exist.\n"
                   "- This is not an Apple ][ disk.\n"
                   "- The disk is 13-sector only.\n"
                   "- The disk is unformatted.\n\n",
    "fatal220f":   "\n"
                   "Passport does not work on this disk.\n\n"
                   "Possible reasons:\n"
                   "- This is not a 13- or 16-sector disk.\n"
                   "- The disk modifies its RWTS in ways\n"
                   "  that Passport is not able to detect.\n\n",
    "modify":      "T{track},S{sector},${offset}: {old_value} -> {new_value}\n",
    "dos33boot0":  "T00,S00 Found DOS 3.3 bootloader\n",
    "dos32boot0":  "T00,S00 Found DOS 3.2 bootloader\n",
    "prodosboot0": "T00,S00 Found ProDOS bootloader\n",
    "pascalboot0": "T00,S00 Found Pascal bootloader\n",
    "mecc":        "T00,S00 Found MECC bootloader\n",
    "sierra":      "T{track},S{sector} Found Sierra protection check\n",
    "a6bc95":      "T{track},S{sector} Found A6BC95 protection check\n",
    "jmpbcf0":     "T00,S03 RWTS requires a timing bit after\n"
                   "the first data epilogue by jumping to\n"
                   "$BCF0.\n",
    "rol1e":       "T00,S03 RWTS accumulates timing bits in\n"
                   "$1E and checks its value later.\n",
    "runhello":    "T{track},S{sector} Startup program executes a\n"
                   "protection check before running the real\n"
                   "startup program.\n",
    "e7":          "T{track},S{sector} Found E7 bitstream\n",
    "jmpb4bb":     "T{track},S{sector} Disk calls a protection check at\n"
                   "$B4BB before initializing DOS.\n",
    "jmpb400":     "T{track},S{sector} Disk calls a protection check at\n"
                   "$B400 before initializing DOS.\n",
    "jmpbeca":     "T00,S02 RWTS requires extra nibbles and\n"
                   "timing bits after the data prologue by\n"
                   "jumping to $BECA.\n",
    "jsrbb03":     "T00,S05 Found a self-decrypting\n"
                   "protection check at $BB03.\n",
    "thunder":     "T00,S03 RWTS counts timing bits and\n"
                   "checks them later.\n",
    "jmpae8e":     "T00,S0D Disk calls a protection check at\n"
                   "$AE8E after initializing DOS.\n",
    "diskvol":     "T00,S08 RWTS requires a non-standard\n"
                   "disk volume number.\n",
    "d5d5f7":      "T{track},S{sector} Found D5D5F7 protection check\n",
    "construct":   "T01,S0F Reconstructing missing data\n",
    "datasoftb0":  "T00,S00 Found Datasoft bootloader\n",
    "datasoft":    "T{track},S{sector} Found Datasoft protection check\n",
    "lsr6a":       "T{track},S{sector} RWTS accepts $D4 or $D5 for the\n"
                   "first address prologue nibble.\n",
    "bcs08":       "T{track},S{sector} RWTS accepts $DE or a timing bit\n"
                   "for the first address epilogue nibble.\n",
    "jmpb660":     "T00,S02 RWTS requires timing bits after\n"
                   "the data prologue by jumping to $B660.\n",
    "protdos":     "T00,S01 Found encrypted RWTS, key=${key}\n",
    "protdosw":    "T00 Decrypting RWTS before writing\n",
    "protserial":  "T{track},S{sector} Erasing serial number {serial}\n",
    "fbff":        "T{track},S{sector} Found FBFF protection check\n",
    "encoded44":   "\n"
                   "T00,S00 Fatal error\n\n"
                   "Passport does not work on this disk,\n"
                   "because it uses a 4-and-4 encoding.\n",
    "encoded53":   "\n"
                   "T00,S00 Fatal error\n\n"
                   "Passport does not work on this disk,\n"
                   "because it uses a 5-and-3 encoding.\n",
    "specdel":     "T00,S00 Found DOS 3.3P bootloader\n",
    "bytrack":     "T{track},S{sector} RWTS changes based on track\n",
    "a5count":     "T{track},S{sector} Found A5 nibble count\n",
    "restart":     "Restarting scan\n",
    "corrupter":   "T13,S0E Protection check intentionally\n"
                   "destroys unauthorized copies\n",
    "eaboot0":     "T00 Found Electronic Arts bootloader\n",
    "eatrk6":      "T06 Found EA protection track\n",
    "poke":        "T{track},S{sector} BASIC program POKEs protection\n"
                   "check into memory and CALLs it.\n",
    "bootcounter": "T{track},S{sector} Original disk destroys itself\n"
                   "after a limited number of boots.\n",
    "milliken":    "T00,S0A Found Milliken protection check\n"
                   "T02,S05 might be unreadable\n",
    "jsr8b3":      "T00,S00 Found JSR $08B3 bootloader\n",
    "daviddos":    "T00,S00 Found David-DOS bootloader\n",
    "quickdos":    "T00,S00 Found Quick-DOS bootloader\n",
    "diversidos":  "T00,S00 Found Diversi-DOS bootloader\n",
    "prontodos":   "T00,S00 Found Pronto-DOS bootloader\n",
    "jmpb412":     "T02,S00 Disk calls a protection check\n"
                   "at $B412 before initializing DOS.\n",
    "laureate":    "T00,S00 Found Laureate bootloader\n",
    "bbf9":        "T{track},S{sector} Found BBF9 protection check\n",
    "micrograms":  "T00,S00 Found Micrograms bootloader\n",
    "cmpbne0":     "T{track},S{sector} RWTS accepts any value for the\n"
                   "first address epilogue nibble.\n",
    "d5timing":    "T{track},S{sector} RWTS accepts $D5 plus a timing\n"
                   "bit as the entire address prologue.\n",
    "advint":      "T{track},S{sector} Found Adventure International\n"
                   "protection check\n",
    "bootwrite":   "T00,S00 Writing Standard Delivery\n"
                   "bootloader\n",
    "rwtswrite":   "T00,S02 Writing built-in RWTS\n",
    "rdos":        "T00,S00 Found RDOS bootloader\n",
    "sra":         "T{track},S{sector} Found SRA protection check\n",
    "muse":        "T00,S08 RWTS doubles every sector ID\n",
    "origin":      "T{track},S{sector} RWTS alters the sector ID if the\n"
                   "address epilogue contains a timing bit.\n",
    "volumename":  "T{track},S{sector} Volume name is ", # no \n
    "dinkeydos":   "T00,S0B Found Dinkey-DOS\n",
    "trillium":    "T{track},S{sector} Found Trillium protection check\n",
    "tamper":      "T{track},S{sector} Found anti-tamper check\n",
    "microfun":    "T{track},S{sector} Found Micro Fun protection check\n",
}
