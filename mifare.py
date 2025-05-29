# -*- coding: utf-8 -*-

"""
Module implementing common.
"""

class Mifare:
    """
    Class documentation goes here.
    """

    @classmethod
    def mifare_value_block_update(cls, value, addr):
        block = []
        block.append((value >>  0) & 0xFF)
        block.append((value >>  8) & 0xFF)
        block.append((value >> 16) & 0xFF)
        block.append((value >> 24) & 0xFF)
        nvalue = ~value
        block.append((nvalue >>  0) & 0xFF)
        block.append((nvalue >>  8) & 0xFF)
        block.append((nvalue >> 16) & 0xFF)
        block.append((nvalue >> 24) & 0xFF)
        block.append((value >>  0) & 0xFF)
        block.append((value >>  8) & 0xFF)
        block.append((value >> 16) & 0xFF)
        block.append((value >> 24) & 0xFF)
        naddr = ~addr
        block.append(addr & 0xFF)
        block.append(naddr & 0xFF)
        block.append(addr & 0xFF)
        block.append(naddr & 0xFF)
        print('Value block new: ', end='')
        for i, v in enumerate(block):
            if i == len(block) - 1:
                print('{:0>2X}'.format(v))
            else:
                print('{:0>2X} '.format(v), end='')
        return block

    @classmethod
    def mifare_value_block_parse(cls, block):
        if len(block) < 16:
            print('value length error!')
            return

        print('Value data: ', end='')
        for i, v in enumerate(block):
            if i == len(block) - 1:
                print('{:0>2X}'.format(v))
            else:
                print('{:0>2X} '.format(v), end='')

        value1 = int.from_bytes(bytes(block[0:4]), byteorder='little', signed=False)
        nvalue = int.from_bytes(bytes(block[4:8]), byteorder='little', signed=False)
        nnvalue = [~x&0xFF for x in block[4:8]]
        nnvalue = int.from_bytes(bytes(nnvalue), byteorder='little', signed=False)
        value2 = int.from_bytes(bytes(block[8:12]), byteorder='little', signed=False)

        addr1 = int.from_bytes(bytes(block[12:13]), byteorder='little', signed=False)
        naddr1 = int.from_bytes(bytes(block[13:14]), byteorder='little', signed=False)
        nnaddr1 = [~block[13] & 0xFF]
        nnaddr1 = int.from_bytes(bytes(nnaddr1), byteorder='little', signed=False)
        addr2 = int.from_bytes(bytes(block[14:15]), byteorder='little', signed=False)
        naddr2 = int.from_bytes(bytes(block[15:16]), byteorder='little', signed=False)

        if value1 != value2 or value1 != nnvalue:
            print('value data error!')
        if addr1 != addr2 or naddr1 != naddr2 or addr1 != nnaddr1:
            print('addr data error!')
        print('Value: {:08X} {:08X} {:08X}'.format(value1, nvalue,value2))
        print('Addr: {:02X} {:02X} {:02X} {:02X}'.format(addr1, naddr1, addr2, naddr2))

    @classmethod
    def mifare_access_update(cls, origin, num, c1c2c3):
        if len(origin) < 3:
            print('origin access bits length error!')
            return
        print('Origin access: ', end='')
        for i, v in enumerate(origin):
            if i == len(origin) - 1:
                print('{:0>2X}'.format(v))
            else:
                print('{:0>2X} '.format(v), end='')
        if num == 0:
            origin[0] = origin[0] & (~0x11) | (0 if c1c2c3 & 0x02 else 1 << 4) | (0 if c1c2c3 & 0x04 else 1 << 0)
            origin[1] = origin[1] & (~0x11) | (1 << 4 if c1c2c3 & 0x04 else 0) | (0 if c1c2c3 & 0x01 else 1 << 0)
            origin[2] = origin[2] & (~0x11) | (1 << 4 if c1c2c3 & 0x01 else 0) | (1 << 0 if c1c2c3 & 0x02 else 0)
        elif num == 1:
            origin[0] = origin[0] & (~0x22) | (0 if c1c2c3 & 0x02 else 1 << 5) | (0 if c1c2c3 & 0x04 else 1 << 1)
            origin[1] = origin[1] & (~0x22) | (1 << 5 if c1c2c3 & 0x04 else 0) | (0 if c1c2c3 & 0x01 else 1 << 1)
            origin[2] = origin[2] & (~0x22) | (1 << 5 if c1c2c3 & 0x01 else 0) | (1 << 1 if c1c2c3 & 0x02 else 0)
        elif num == 2:
            origin[0] = origin[0] & (~0x44) | (0 if c1c2c3 & 0x02 else 1 << 6) | (0 if c1c2c3 & 0x04 else 1 << 2)
            origin[1] = origin[1] & (~0x44) | (1 << 6 if c1c2c3 & 0x04 else 0) | (0 if c1c2c3 & 0x01 else 1 << 2)
            origin[2] = origin[2] & (~0x44) | (1 << 6 if c1c2c3 & 0x01 else 0) | (1 << 2 if c1c2c3 & 0x02 else 0)
        elif num == 3:
            origin[0] = origin[0] & (~0x88) | (0 if c1c2c3 & 0x02 else 1 << 7) | (0 if c1c2c3 & 0x04 else 1 << 3)
            origin[1] = origin[1] & (~0x88) | (1 << 7 if c1c2c3 & 0x04 else 0) | (0 if c1c2c3 & 0x01 else 1 << 3)
            origin[2] = origin[2] & (~0x88) | (1 << 7 if c1c2c3 & 0x01 else 0) | (1 << 3 if c1c2c3 & 0x02 else 0)
        else:
            print('Block num error {}!'.format(num))
            return
        print('New access: ', end='')
        for i, v in enumerate(origin):
            if i == len(origin) - 1:
                print('{:0>2X}'.format(v))
            else:
                print('{:0>2X} '.format(v), end='')
        return origin

    @classmethod
    def mifare_access_parse(cls, access = [0xff, 0x07, 0x80, 0x69]):
        if len(access) < 3:
            print('Access bits length error!')
            return
        for i, v in enumerate(access):
            if i == len(access) - 1:
                print('{:0>2X}'.format(v))
            else:
                print('{:0>2X} '.format(v), end='')
        if (access[1]>>4) & 0x0F != (~access[0]) & 0x0F:
            print('C1 format error {:X} {:X}!'.format((access[1]>>4) & 0x0F, (~access[0]) & 0x0F))
            return
        elif access[2] & 0x0F != (~(access[0]>>4)) & 0x0F:
            print('C2 format error {:X} {:X}!'.format(access[2] & 0x0F, (~(access[0]>>4)) & 0x0F))
            return
        elif (access[2]>>4) & 0x0F != (~(access[1])) & 0x0F:
            print('C3 format error {:X} {:X}!'.format((access[2]>>4) & 0x0F, (~(access[1])) & 0x0F))
            return
        Blk0C1C2C3 = (1 if access[1]&0x10 else 0) << 2 | \
                    (1 if access[2]&0x01 else 0) << 1 | \
                    (1 if access[2]&0x10 else 0)
        print('Blk0C1C2C3: {:0>3b}'.format(Blk0C1C2C3))
        Blk1C1C2C3 = (1 if access[1]&0x20 else 0) << 2 | \
                    (1 if access[2]&0x02 else 0) << 1 | \
                    (1 if access[2]&0x20 else 0)
        print('Blk1C1C2C3: {:0>3b}'.format(Blk1C1C2C3))
        Blk2C1C2C3 = (1 if access[1]&0x40 else 0) << 2 | \
                    (1 if access[2]&0x04 else 0) << 1 | \
                    (1 if access[2]&0x40 else 0)
        print('Blk2C1C2C3: {:0>3b}'.format(Blk2C1C2C3))
        TailC1C2C3 = (1 if access[1]&0x80 else 0) << 2 | \
                    (1 if access[2]&0x08 else 0) << 1 | \
                    (1 if access[2]&0x80 else 0)
        print('TailC1C2C3: {:0>3b}'.format(TailC1C2C3))

    @classmethod
    def mifare_test_case(cls):
        # 6/7/8/9 字节：访问权限解析
        c1c2c3 = [0xff, 0x07, 0x80, 0x69]
        Mifare.mifare_access_parse(c1c2c3)
        # 更新指定块访问权限，块号为扇区内编号
        c1c2c3 = Mifare.mifare_access_update(c1c2c3, 0, 0x02)
        Mifare.mifare_access_parse(c1c2c3)
        # 解析值块数据
        value = [0x72, 0x6f, 0x6f, 0x6d, 0x24, 0x33, 0x30, 0x30, 
                0x24, 0x38, 0x39, 0x33, 0x32, 0x36, 0x39, 0x35]
        Mifare.mifare_value_block_parse(value)
        # 生成指定值块数值和地址
        value = 0x12345678
        addr = 5
        new = Mifare.mifare_value_block_update(value, addr)
        Mifare.mifare_value_block_parse(new)

if __name__ == '__main__':
    value = [0x78, 0x56, 0x34, 0x12, 0x87, 0xa9, 0xcb, 0xed,
             0x78, 0x56, 0x34, 0x12, 0x05, 0xfa, 0x05, 0xfa]
    Mifare.mifare_value_block_parse(value)
    value = [0x77, 0x56, 0x34, 0x12, 0x88, 0xa9, 0xcb, 0xed,
             0x77, 0x56, 0x34, 0x12, 0x05, 0xfa, 0x05, 0xfa]
    Mifare.mifare_value_block_parse(value)
