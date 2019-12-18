
import struct

import click
import whvp

from tracer import Tracer, RpycConnection


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


@click.command()
@click.argument("context", required=False)
@click.option("--connection", default="localhost:18861", show_default=True)
@click.option("--coverage", type=click.Choice(["no", "hit", "instrs", "bbl"]), default="instrs", show_default=True)
@click.option("--max-time", type=int, default=0, show_default=True)
@click.option("--max-iterations", type=int, default=0, show_default=True)
@click.option("--input", required=True)
@click.option("--input-size", required=True)
@click.option("--input-type", type=click.Choice(["mem", "reg"]), default="mem", show_default=True)
def cli(context, connection, coverage, max_time, max_iterations, input, input_type, input_size):
    emulator = whvp.Emulator()

    hostname, port = connection.split(":")
    connection = RpycConnection(hostname, int(port))

    tracer = Tracer(emulator, connection)

    context = connection.get_initial_context()

    rip = context["rip"]
    name = tracer.get_formatted_symbol(rip)
    print(F"fuzzing {name} ({rip:x})")

    fuzzer = whvp.Fuzzer()

    stopping_functions = ["nt!KeYieldProcessorEx",
                "nt!KeBugCheckEx",
                "nt!KiIpiSendRequestEx",
                "nt!KdpReport",
                "nt!KdEnterDebugger",
                "nt!KeFreezeExecution",
                "nt!KiExceptionDispatch"]

    symbols = {}
    stopping_addresses = []
    for name in stopping_functions:
        address = connection.get_address(name)
        if address is not None:
            print(F"found {name} @ {address:x}")
            stopping_addresses.append(address)
            symbols[address] = name

    # data: poi(poi(poi(sdbparser!SdbHandle)+8)+8)
    # size: poi(poi(sdbparser!SdbHandle)+8)+0x10)

    input_value = connection.system.expr(input)
    print(F"input is {input_value:x}")
    input_size = connection.system.expr(input_size)
    print(F"input size is {input_size:x}")

    params = {
        "coverage_mode": coverage,
        "return_address": context["return_address"],
        "save_context": False,
        "stopping_addresses": stopping_addresses,
        "max_iterations": max_iterations,
        "max_time": max_time,
        "input": input_value,
        "input_type": input_type,
        "input_size": input_size
    }

    def report_callback(emulator, data):
        rip = emulator.get_reg("rip")
        name = symbols.get(rip)
        print(F"got abnormal exit on {name} {rip:x}")
        print(hexdump(0, data))

    print("running fuzzer")
    fuzzer.run(emulator, context, params, tracer.memory_access_callback, report_callback)


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
