from passport.rwts.dos33 import DOS33RWTS

class BorderRWTS(DOS33RWTS):
    # TODO doesn't work yet, not sure why
    def reset(self, logical_sectors):
        DOS33RWTS.reset(self, logical_sectors)
        self.address_prologue = (logical_sectors[9][0x16],
                                 logical_sectors[9][0x1B],
                                 logical_sectors[9][0x20])
        self.address_epilogue = (logical_sectors[9][0x25],
                                 logical_sectors[9][0x2A])
        self.data_prologue = (logical_sectors[8][0xFD],
                              logical_sectors[9][0x02],
                              logical_sectors[9][0x02])
        self.data_epilogue = (logical_sectors[9][0x0C],
                              logical_sectors[9][0x11])
