from passport.rwts import RWTS

class DOS33RWTS(RWTS):
    def __init__(self, logical_sectors, g):
        self.g = g
        self.reset(logical_sectors)
        RWTS.__init__(self,
                      g,
                      sectors_per_track=16,
                      address_prologue=self.address_prologue,
                      address_epilogue=self.address_epilogue,
                      data_prologue=self.data_prologue,
                      data_epilogue=self.data_epilogue,
                      nibble_translate_table=self.nibble_translate_table)

    def reset(self, logical_sectors):
        self.address_prologue = (logical_sectors[3][0x55],
                                 logical_sectors[3][0x5F],
                                 logical_sectors[3][0x6A])
        self.address_epilogue = (logical_sectors[3][0x91],
                                 logical_sectors[3][0x9B])
        self.data_prologue = (logical_sectors[2][0xE7],
                              logical_sectors[2][0xF1],
                              logical_sectors[2][0xFC])
        self.data_epilogue = (logical_sectors[3][0x35],
                              logical_sectors[3][0x3F])
        self.nibble_translate_table = {}
        for nibble in range(0x96, 0x100):
            self.nibble_translate_table[nibble] = logical_sectors[4][nibble]
