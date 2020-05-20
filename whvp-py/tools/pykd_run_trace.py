
import click
import json

import pykd


def format_regs(regs):
    return F"""rax = 0x{regs["rax"]:>016x} rbx = 0x{regs["rbx"]:>016x} rcx = 0x{regs["rcx"]:>016x} rdx = 0x{regs["rdx"]:>016x}
rbp = 0x{regs["rbp"]:>016x} rsp = 0x{regs["rsp"]:>016x} rdi = 0x{regs["rdi"]:>016x} rsi = 0x{regs["rsi"]:>016x}
r8  = 0x{regs["r8"]:>016x} r9  = 0x{regs["r9"]:>016x} r10 = 0x{regs["r10"]:>016x} r11 = 0x{regs["r11"]:>016x}
r12 = 0x{regs["r12"]:>016x} r13 = 0x{regs["r13"]:>016x} r14 = 0x{regs["r14"]:>016x} r15 = 0x{regs["r15"]:>016x}
rfl = 0x{regs["rflags"]:>016x}"""


@click.command()
@click.argument("trace")
@click.option("--limit", type=int, default=0, show_default=True)
def cli(trace, limit):

    with open(trace, "r") as fp:
        trace = json.load(fp)

    total = len(trace["coverage"])
    if limit != 0:
        coverage = trace["coverage"][-limit:]
    else:
        coverage = trace["coverage"]
    for index, (address, context) in enumerate(coverage):
        if limit != 0:
            print(F"[instruction {total - limit + index + 1} / {total}]")
        else:
            print(F"[instruction {index + 1} / {total}]")
        if context:
            print(format_regs(context))
        disass = pykd.dbgCommand(F"u {address:x} L1")
        lines = disass.splitlines()
        print(lines[0].split()[0])
        print(lines[1])

        print("")


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
