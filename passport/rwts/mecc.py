from passport.rwts.dos33 import DOS33RWTS

class MECCRWTS(DOS33RWTS):
    # MECC fastloaders
    def __init__(self, mecc_variant, logical_sectors, g):
        g.mecc_variant = mecc_variant
        DOS33RWTS.__init__(self, logical_sectors, g)

    def reset(self, logical_sectors):
        self.nibble_translate_table = self.kDefaultNibbleTranslationTable16
        self.address_epilogue = (0xDE, 0xAA)
        self.data_epilogue = (0xDE, 0xAA)
        if self.g.mecc_variant == 1:
            self.address_prologue = (logical_sectors[0x0B][0x08],
                                     logical_sectors[0x0B][0x12],
                                     logical_sectors[0x0B][0x1D])
            self.data_prologue = (logical_sectors[0x0B][0x8F],
                                  logical_sectors[0x0B][0x99],
                                  logical_sectors[0x0B][0xA3])
        elif self.g.mecc_variant == 2:
            self.address_prologue = (logical_sectors[7][0x83],
                                     logical_sectors[7][0x8D],
                                     logical_sectors[7][0x98])
            self.data_prologue = (logical_sectors[7][0x15],
                                  logical_sectors[7][0x1F],
                                  logical_sectors[7][0x2A])
        elif self.g.mecc_variant == 3:
            self.address_prologue = (logical_sectors[0x0A][0xE8],
                                     logical_sectors[0x0A][0xF2],
                                     logical_sectors[0x0A][0xFD])
            self.data_prologue = (logical_sectors[0x0B][0x6F],
                                  logical_sectors[0x0B][0x79],
                                  logical_sectors[0x0B][0x83])
        elif self.g.mecc_variant == 4:
            self.address_prologue = (logical_sectors[8][0x83],
                                     logical_sectors[8][0x8D],
                                     logical_sectors[8][0x98])
            self.data_prologue = (logical_sectors[8][0x15],
                                  logical_sectors[8][0x1F],
                                  logical_sectors[8][0x2A])
