
import struct
import colorama


FMTS = {1: "b",
        2: "h",
        4: "i",
        8: "q"}


def get_bits(value, pos, width):
    mask = 2**width - 1
    return (value >> pos) & mask


def set_bits(orig, pos, width, value):
    mask = 2**width - 1
    value = (value & mask) << pos
    mask = mask << pos
    return orig & ~mask | value


def get_fmt(size, bigendian, unsigned):
    fmt = ">" if bigendian else "<"
    fmt += FMTS[size].upper() if unsigned else FMTS[size]
    return fmt


def hexdump(addr, data, size=1, ascii=True):
    res = []
    fmt = "%%0%dx " % (size * 2)

    for i in range(0, len(data), 16):
        line = "0x%08x: " % (addr + i)

        for j in range(0, 16, size):
            if j == 8:
                line += "  "
            if i + j >= len(data):
                line += "   "
            else:
                value = struct.unpack(get_fmt(size, False, True),
                        data[i + j:i + j + size])
                line += fmt % (value)

        if ascii:
            line += " |"
            for j in range(0, 16):
                if i + j >= len(data):
                    break
                if 0x30 <= data[i + j] <= 0x7e:
                    line += "%c" % data[i + j]
                else:
                    line += "."
            line += "|"

        res.append(line)
    return "\n".join(res)


def format_regs(regs):
    return F"""rax = 0x{regs["rax"]:>016x} rbx = 0x{regs["rbx"]:>016x} rcx = 0x{regs["rcx"]:>016x} rdx = 0x{regs["rdx"]:>016x}
rbp = 0x{regs["rbp"]:>016x} rsp = 0x{regs["rsp"]:>016x} rdi = 0x{regs["rdi"]:>016x} rsi = 0x{regs["rsi"]:>016x}
r8  = 0x{regs["r8"]:>016x} r9  = 0x{regs["r9"]:>016x} r10 = 0x{regs["r10"]:>016x} r11 = 0x{regs["r11"]:>016x}
r12 = 0x{regs["r12"]:>016x} r13 = 0x{regs["r13"]:>016x} r14 = 0x{regs["r14"]:>016x} r15 = 0x{regs["r15"]:>016x}
rfl = 0x{regs["rflags"]:>016x}"""


class Input(object):

    def __init__(self, address, data):
        self.address = address
        self.size = len(data)
        self.data = data

    def format(self):
        data = []
        for offset, value in enumerate(self.data):
            if offset != 0 and offset % 0x10 == 0:
                data.append("\n")
            byte = "%02x " % (value)
            data.append(colorama.Fore.WHITE + byte + colorama.Fore.RESET)

        return "".join(data)

    def diff(self, other):
        data = []
        for offset, value in enumerate(self.data):
            if offset != 0 and offset % 0x10 == 0:
                data.append("\n")

            if offset < len(other):
                other_value = other[offset]
                if other_value != value:
                    byte = "%02x " % (other_value)
                    data.append(colorama.Fore.RED + byte + colorama.Fore.RESET)
                else:
                    byte = "%02x " % (value)
                    data.append(colorama.Fore.WHITE + byte + colorama.Fore.RESET)
            else:
                byte = "%02x " % (value)
                data.append(colorama.Fore.WHITE + byte + colorama.Fore.RESET)

        return "".join(data)


