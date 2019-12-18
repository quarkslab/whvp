
import os
import json

import click

import whvp

from tracer import Tracer, ModuleManager


class FileConnection(object):

    def __init__(self, path):
        self.path = path
        self._symbols = {}
        path = os.path.join(self.path, "symbols.json")
        if os.path.exists(path):
            with open(path, "r") as fp:
                self._symbols = json.load(fp)

        self._addresses = {}
        for address, name in self._symbols.items():
            self._addresses[name] = int(address)

        path = os.path.join(self.path, "trace", "trace.json")
        with open(path, "r") as fp:
            self._trace = json.load(fp)

        self.modules = ModuleManager()
        self.modules._modules = self._trace["modules"]

    def get_initial_context(self):
        path = os.path.join(self.path, "partition", "context.json")
        if os.path.exists(path):
            with open(path, "r") as fp:
                context = json.load(fp)

            return context

    def memory_access_callback(self, gpa):
        base = gpa & ~0xfff
        path = os.path.join(self.path, "partition", "mem", "%016x.bin" % (base))
        if os.path.exists(path):
            with open(path, "rb") as fp:
                data = fp.read()
                return data

    def get_formatted_symbol(self, address):
        symbol = self._symbols.get(str(address))
        return symbol

    def get_address(self, name):
        address = self._addresses.get(name)
        return address

    def get_module(self, address):
        return self.modules.get_module(address)


@click.command()
@click.argument("context", required=False)
@click.option("--trace", required=True)
@click.option("--export")
@click.option("--coverage", type=click.Choice(["no", "hit", "instrs", "bbl"]), default="instrs", show_default=True)
@click.option("--save-instruction-context", is_flag=True)
def cli(context, trace, export, coverage, save_instruction_context):
    emulator = whvp.Emulator()

    connection = FileConnection(trace)

    tracer = Tracer(emulator,
                    connection,
                    workdir=export,
                    coverage_mode=coverage,
                    save_instruction_context=save_instruction_context)

    tracer.run()


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
