from passport.rwts.dos33 import DOS33RWTS

class LaureateRWTS(DOS33RWTS):
    # nibble table is in T00,S06
    # address prologue is T00,S05 A$55,A$5F,A$6A
    # address epilogue is T00,S05 A$91,A$9B
    # data prologue is T00,S04 A$E7,A$F1,A$FC
    # data epilogue is T00,S05 A$35,A$3F
    def reset(self, logical_sectors):
        self.address_prologue = (logical_sectors[5][0x55],
                                 logical_sectors[5][0x5F],
                                 logical_sectors[5][0x6A])
        self.address_epilogue = (logical_sectors[5][0x91],
                                 logical_sectors[5][0x9B])
        self.data_prologue = (logical_sectors[4][0xE7],
                              logical_sectors[4][0xF1],
                              logical_sectors[4][0xFC])
        self.data_epilogue = (logical_sectors[5][0x35],
                              logical_sectors[5][0x3F])
        self.nibble_translate_table = {}
        for nibble in range(0x96, 0x100):
            self.nibble_translate_table[nibble] = logical_sectors[6][nibble]
