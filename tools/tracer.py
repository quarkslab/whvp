
import os
import time
import json

import click
import rpyc
import whvp


class RpycConnection(object):

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port

        conn = rpyc.connect(self.hostname, self.port, config={"allow_all_attrs": True})
        self.system = conn.root

    def get_initial_context(self):
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
        return context

    def memory_access_callback(self, gpa):
        base = gpa & ~0xfff
        data = self.system.read_physical_address(base, 0x1000)
        return data

    def get_formatted_symbol(self, address):
        try:
            return self.system.get_formatted_symbol(address)
        except Exception:
            return None

    def get_address(self, name):
        try:
            return self.system.get_address(name)
        except Exception:
            return None

    def get_module(self, address):
        return self.system.get_module(address)


class ModuleManager(object):

    def __init__(self):
        self._modules = {}

    def add_module(self, module):
        start = module.begin()
        end = module.end()
        size = module.size()
        name = module.name()
        image = module.image()
        self._modules[name] = {"start": start, "end": end, "size": size, "image": image}

    def is_address_in_module(self, address, module):
        return module["start"] <= address < module["start"] + module["size"]

    def get_module(self, address):
        for module in self._modules.values():
            if self.is_address_in_module(address, module):
                return module

    def has_address(self, address):
        module = self.get_module(address)
        return module is not None


class Tracer(object):

    def __init__(self, emulator, connection, workdir=None,
                 coverage_mode=None, save_instruction_context=False):
        self.emulator = emulator
        self.connection = connection

        self.workdir = workdir
        self.coverage_mode = coverage_mode

        if workdir is not None:
            os.makedirs(os.path.join(workdir, "trace"), exist_ok=True)
            os.makedirs(os.path.join(workdir, "partition", "mem"), exist_ok=True)
            os.makedirs(os.path.join(workdir, "partition", "vmem"), exist_ok=True)

        self.save_instruction_context = save_instruction_context
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

    def save_result(self, result):
        if self.workdir is not None:
            coverage = result.get_coverage()
            context = result.get_context()
            modules = ModuleManager()
            for address in coverage:
                if not modules.has_address(address):
                    module = self.connection.get_module(address)
                    modules.add_module(module)

            path = os.path.join(self.workdir, "trace", "trace.json")
            with open(path, "w") as fp:
                data = {}
                data["addresses"] = coverage
                data["context"] = context
                data["modules"] = modules._modules
                json.dump(data, fp, indent=2)

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

    def memory_access_callback(self, gpa, gva):
        data = self.connection.memory_access_callback(gpa)
        if data:
            if self.workdir is not None:
                base = gpa & ~0xfff
                path = os.path.join(self.workdir, "partition", "mem", "%016x.bin" % (base))
                with open(path, "wb") as fp:
                    fp.write(data)
                if gva != 0:
                    base = gva & ~0xfff
                    path = os.path.join(self.workdir, "partition", "vmem", "%016x.bin" % (base))
                    with open(path, "wb") as fp:
                        fp.write(data)

            return data
        else:
            raise Exception(F"no data for gpa {gpa:X}")

    def get_formatted_symbol(self, address):
        symbol = self._symbols.get(str(address))
        if symbol is None:
            symbol = self.connection.get_formatted_symbol(address)
            self._symbols[address] = symbol
        return symbol

    def run(self):
        print("get initial context")
        context = self.connection.get_initial_context()

        self.save_context(context)

        rip = context["rip"]
        name = self.get_formatted_symbol(rip)
        print(F"tracing {name} ({rip:x})")

        stopping_functions = ["nt!KeYieldProcessorEx",
                "nt!KeBugCheckEx",
                "nt!KiIpiSendRequestEx",
                "nt!KiExceptionDispatch",
                "nt!KdpReport",
                "nt!KdEnterDebugger",
                "nt!KeFreezeExecution"]

        stopping_addresses = []
        for name in stopping_functions:
            address = self.connection.get_address(name)
            if address is not None:
                print(F"{name} {address:x}")
                stopping_addresses.append(address)

        self.set_context(context)

        params = {
            "coverage_mode": self.coverage_mode,
            "return_address": context["return_address"],
            "save_context": self.save_instruction_context,
            "stopping_addresses": stopping_addresses
        }

        print("running emulator")
        start = time.time()
        result = self.emulator.run_until(params, memory_access_callback=self.memory_access_callback)
        end = time.time()
        print(F"{result} in {end - start:.2f} secs")

        self.save_result(result)
        self.save_symbols()


@click.command()
@click.argument("context", required=False)
@click.option("--connection", default="localhost:18861", show_default=True)
@click.option("--coverage", type=click.Choice(["no", "hit", "instrs", "bbl"]), default="instrs", show_default=True)
@click.option("--export")
@click.option("--save-instruction-context", is_flag=True)
def cli(context, connection, coverage, export, save_instruction_context):
    emulator = whvp.Emulator()

    hostname, port = connection.split(":")
    connection = RpycConnection(hostname, int(port))

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
