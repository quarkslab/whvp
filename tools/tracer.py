
import os
import time
import json

import click
import rpyc
import whvp


class Tracer(object):

    def __init__(self, emulator, connection=None, connection_params=None, workdir=None,
                 coverage_mode=None, save_context=False, resolve_symbols=False):
        self.emulator = emulator
        self.system = None
        if connection is None:
            self.connection = "rpyc"
        else:
            self.connection = connection

        if connection_params is None:
            self.connection_params = "localhost:18861"
        else:
            self.connection_params = connection_params

        self.workdir = workdir
        self.coverage_mode = coverage_mode
        self.resolve_symbols = resolve_symbols
        if workdir is not None:
            os.makedirs(os.path.join(workdir, "trace"), exist_ok=True)
            os.makedirs(os.path.join(workdir, "partition", "mem"), exist_ok=True)

        self._save_context = save_context
        self.load_symbols()

    def load_symbols(self):
        self._symbols = {}
        if self.workdir is not None:
            path = os.path.join(self.workdir, "symbols.json")
            if os.path.exists(path):
                with open(path, "r") as fp:
                    self._symbols = json.load(fp)
                print(F"loaded {len(self._symbols.keys())} symbols")

    def save_symbols(self):
        if self.workdir is not None:
            path = os.path.join(self.workdir, "symbols.json")
            with open(path, "w") as fp:
                json.dump(self._symbols, fp, indent=2)

    def save_context(self, context):
        if self.workdir is not None:
            filename = os.path.join(self.workdir, "partition", "context.json")
            with open(filename, "w") as fp:
                json.dump(context, fp, indent=2)

    def add_module(self, modules, module):
        start = module.begin()
        end = module.end()
        size = module.size()
        name = module.name()
        image = module.image()
        modules[name] = {"start": start, "end": end, "size": size, "image": image}

    def is_address_in_module(self, address, module):
        return module["start"] <= address < module["start"] + module["size"]

    def has_address(self, modules, address):
        for module in modules.values():
            if self.is_address_in_module(address, module):
                return True

        return False

    def save_result(self, result):
        if self.workdir is not None:
            path = os.path.join(self.workdir, "trace", "trace.txt")
            coverage = result.get_coverage()
            context = result.get_context()
            modules = {}
            with open(path, "w") as fp:
                for address in coverage:
                    if not self.has_address(modules, address):
                        module = self.system.get_module(address)
                        self.add_module(modules, module)
                    if self.resolve_symbols:
                        name = self.get_formatted_symbol(address)
                        fp.write(F"{address:x} ({name})\n")
                    else:
                        fp.write(F"{address:x}\n")
            path = os.path.join(self.workdir, "trace", "trace.json")
            with open(path, "w") as fp:
                data = {}
                data["addresses"] = coverage
                data["context"] = context
                data["modules"] = modules
                json.dump(data, fp, indent=2)

    def connect(self):
        if self.connection == "rpyc":
            hostname, port = self.connection_params.split(":")
            port = int(port)
            conn = rpyc.connect(hostname, port, config={"allow_all_attrs": True})
            self.system = conn.root

    def get_initial_context(self):
        if self.connection == "rpyc":
            system = self.system
            context = {}
            context["gdtr"] = system.get_reg("gdtr")
            context["gdtl"] = system.get_reg("gdtl")

            context["idtr"] = system.get_reg("idtr")
            context["idtl"] = system.get_reg("idtl")

            context["cr0"] = system.get_reg("cr0")
            context["cr3"] = system.get_reg("cr3")
            context["cr4"] = system.get_reg("cr4")
            context["cr8"] = system.get_reg("cr8")
            context["efer"] = system.get_efer()

            context["cs"] = system.get_reg("cs")
            context["ss"] = system.get_reg("ss")
            context["ds"] = system.get_reg("ds")
            context["es"] = system.get_reg("es")

            context["fs"] = system.get_reg("fs")
            context["gs"] = system.get_reg("gs")

            context["fs_base"] = system.get_teb()
            context["gs_base"] = system.get_kpcr()
            context["kernel_gs_base"] = system.get_kernel_gs_base()

            context["sysenter_cs"] = system.get_sysenter_cs()
            context["sysenter_esp"] = system.get_sysenter_esp()
            context["sysenter_eip"] = system.get_sysenter_eip()

            context["rax"] = system.get_reg("rax")
            context["rbx"] = system.get_reg("rbx")
            context["rcx"] = system.get_reg("rcx")
            context["rdx"] = system.get_reg("rdx")
            context["rsi"] = system.get_reg("rsi")
            context["rdi"] = system.get_reg("rdi")
            context["r8"] = system.get_reg("r8")
            context["r9"] = system.get_reg("r9")
            context["r10"] = system.get_reg("r10")
            context["r11"] = system.get_reg("r11")
            context["r12"] = system.get_reg("r12")
            context["r13"] = system.get_reg("r13")
            context["r14"] = system.get_reg("r14")
            context["r15"] = system.get_reg("r15")

            context["rbp"] = system.get_reg("rbp")
            context["rsp"] = system.get_reg("rsp")

            context["rip"] = system.get_reg("rip")
            context["rflags"] = system.get_reg("efl")

            context["return_address"] = system.read_qword(system.get_reg("rsp"))

        if self.connection == "file":
            path = os.path.join(self.connection_params, "context.json")
            if os.path.exists(path):
                with open(path, "r") as fp:
                    context = json.load(fp)

        return context

    def set_context(self, context):
        emulator = self.emulator
        emulator.set_table_reg("gdt", context["gdtr"], context["gdtl"])
        emulator.set_table_reg("idt", context["idtr"], context["idtl"])

        emulator.set_reg("cr0", context["cr0"])
        emulator.set_reg("cr3", context["cr3"])
        emulator.set_reg("cr4", context["cr4"])
        emulator.set_reg("cr8", context["cr8"])
        emulator.set_reg("efer", context["efer"])

        emulator.set_segment_reg("cs", 0, 0, 1, 0, context["cs"])
        emulator.set_segment_reg("ss", 0, 0, 0, 0, context["ss"])
        emulator.set_segment_reg("ds", 0, 0, 0, 0, context["ds"])
        emulator.set_segment_reg("es", 0, 0, 0, 0, context["es"])

        emulator.set_segment_reg("fs", context["fs_base"], 0, 0, 0, context["fs"])
        emulator.set_segment_reg("gs", context["gs_base"], 0, 0, 0, context["gs"])

        emulator.set_reg("kernel_gs_base", context["kernel_gs_base"])

        emulator.set_reg("rax", context["rax"])
        emulator.set_reg("rbx", context["rbx"])
        emulator.set_reg("rcx", context["rcx"])
        emulator.set_reg("rdx", context["rdx"])
        emulator.set_reg("rsi", context["rsi"])
        emulator.set_reg("rdi", context["rdi"])
        emulator.set_reg("r8", context["r8"])
        emulator.set_reg("r9", context["r9"])
        emulator.set_reg("r10", context["r10"])
        emulator.set_reg("r11", context["r11"])
        emulator.set_reg("r12", context["r12"])
        emulator.set_reg("r13", context["r13"])
        emulator.set_reg("r14", context["r14"])
        emulator.set_reg("r15", context["r15"])

        emulator.set_reg("rbp", context["rbp"])
        emulator.set_reg("rsp", context["rsp"])

        emulator.set_reg("rip", context["rip"])

        emulator.set_reg("rflags", context["rflags"])

    def memory_access_callback(self, gpa):
        base = gpa & ~0xfff
        if self.connection == "rpyc":
            data = self.system.read_physical_address(base, 0x1000)

        if self.connection == "file":
            path = os.path.join(self.connection_params, "mem", "%016x.bin" % (base))
            if os.path.exists(path):
                with open(path, "rb") as fp:
                    data = fp.read()
            else:
                data = None

        if data:
            if self.workdir is not None:
                path = os.path.join(self.workdir, "partition", "mem", "%016x.bin" % (base))
                with open(path, "wb") as fp:
                    fp.write(data)

            return data
        else:
            raise Exception("no data")

    def get_symbol(self, address):
        try:
            return self.system.get_symbol(address)
        except Exception:
            return None

    def get_address(self, name):
        try:
            return self.system.get_address(name)
        except Exception as e:
            print(e)
            return None

    def _get_formatted_symbol(self, address):
        symbol = self.get_symbol(address)
        if symbol is not None:
            return F"{symbol[0]}!{symbol[1]}+0x{symbol[2]:x}"

    def get_formatted_symbol(self, address):
        symbol = self._symbols.get(str(address))
        if symbol is None:
            symbol = self._get_formatted_symbol(address)
            self._symbols[address] = symbol
        return symbol

    def run(self):
        print("get initial context")
        context = self.get_initial_context()

        self.save_context(context)

        rip = context["rip"]
        name = self.get_formatted_symbol(rip)
        print(F"tracing {name} ({rip:x})")

        stopping_functions = ["nt!KeYieldProcessorEx",
                "nt!KeBugCheckEx",
                "nt!KiIpiSendRequestEx",
                "nt!KiExceptionDispatch"]

        stopping_addresses = []
        for name in stopping_functions:
            address = self.get_address(name)
            if address is not None:
                print(F"{name} {address:x}")
                stopping_addresses.append(address)

        self.set_context(context)

        params = {
            "coverage_mode": self.coverage_mode,
            "return_address": context["return_address"],
            "save_context": self._save_context,
            "stopping_addresses": stopping_addresses
        }

        print(params)

        print("running emulator")
        start = time.time()
        result = self.emulator.run_until(params, memory_access_callback=self.memory_access_callback)
        end = time.time()
        print(F"{result} in {end - start:.2f} secs")

        self.save_result(result)
        self.save_symbols()


@click.command()
@click.argument("context", required=False)
@click.option("--connection", type=click.Choice(["rpyc", "local"]), default="rpyc", show_default=True)
@click.option("--connection-params", default="localhost:18861", show_default=True)
@click.option("--coverage", type=click.Choice(["no", "hit", "instrs", "bbl"]), default="instrs", show_default=True)
@click.option("--workdir")
@click.option("--resolve-symbols", is_flag=True)
@click.option("--save-context", is_flag=True)
def cli(context, connection, connection_params, coverage, workdir, resolve_symbols, save_context):
    emulator = whvp.Emulator()

    tracer = Tracer(emulator,
                    connection=connection, connection_params=connection_params,
                    workdir=workdir,
                    coverage_mode=coverage,
                    save_context=save_context,
                    resolve_symbols=resolve_symbols)

    tracer.connect()

    tracer.run()


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
