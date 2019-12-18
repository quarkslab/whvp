
import os
import json
import colorama

import click

import triton


class FileTrace(object):

    def __init__(self, path):
        self.path = path

        path = os.path.join(self.path, "trace", "trace.json")
        with open(path, "r") as fp:
            self.trace = json.load(fp)

    def get_initial_context(self):
        path = os.path.join(self.path, "partition", "context.json")
        if os.path.exists(path):
            with open(path, "r") as fp:
                context = json.load(fp)

            return context

    def load_page(self, address):
        path = os.path.join(self.path, "partition", "vmem", "%016x.bin" % (address))
        if os.path.exists(path):
            with open(path, "rb") as fp:
                data = fp.read()
                return data

    def iter_pages(self):
        path = os.path.join(self.path, "partition", "vmem")
        for filename in os.listdir(path):
            basename, ext = os.path.splitext(filename)
            if ext == ".bin":
                address = int(basename, 16)
                yield address


class TritonEmulator(object):

    def __init__(self, arch=triton.ARCH.X86_64):
        self.context = triton.TritonContext()
        self.context.setArchitecture(arch)

        self.context.enableSymbolicEngine(True)

        self.context.setMode(triton.MODE.ALIGNED_MEMORY, True)
        self.context.setMode(triton.MODE.AST_OPTIMIZATIONS, True)

    def get_context(self, upper=False):
        context = {}
        mapping = [("rax", "rax"),
                   ("rbx", "rbx"),
                   ("rcx", "rcx"),
                   ("rdx", "rdx"),
                   ("rbp", "rbp"),
                   ("rsp", "rsp"),
                   ("rdi", "rdi"),
                   ("rsi", "rsi"),
                   ("r8", "r8"),
                   ("r9", "r9"),
                   ("r10", "r10"),
                   ("r11", "r11"),
                   ("r12", "r12"),
                   ("r13", "r13"),
                   ("r14", "r14"),
                   ("r15", "r15"),
                   ("rflags", "eflags"),
                   ("rip", "rip")]

        for key, reg in mapping:
            if upper:
                key = key.upper()
            context[key] = self.context.getConcreteRegisterValue(getattr(self.context.registers, reg))

        return context

    def set_gs_base(self, gs_base):
        self.context.setConcreteRegisterValue(self.context.registers.gs, gs_base)

    def set_context(self, context):
        self.context.setConcreteRegisterValue(self.context.registers.rsp, context["rsp"])
        self.context.setConcreteRegisterValue(self.context.registers.rbp, context["rbp"])
        self.context.setConcreteRegisterValue(self.context.registers.rax, context["rax"])
        self.context.setConcreteRegisterValue(self.context.registers.rbx, context["rbx"])
        self.context.setConcreteRegisterValue(self.context.registers.rcx, context["rcx"])
        self.context.setConcreteRegisterValue(self.context.registers.rdx, context["rdx"])
        self.context.setConcreteRegisterValue(self.context.registers.rdi, context["rdi"])
        self.context.setConcreteRegisterValue(self.context.registers.rsi, context["rsi"])
        self.context.setConcreteRegisterValue(self.context.registers.r8, context["r8"])
        self.context.setConcreteRegisterValue(self.context.registers.r9, context["r9"])
        self.context.setConcreteRegisterValue(self.context.registers.r10, context["r10"])
        self.context.setConcreteRegisterValue(self.context.registers.r11, context["r11"])
        self.context.setConcreteRegisterValue(self.context.registers.r12, context["r12"])
        self.context.setConcreteRegisterValue(self.context.registers.r13, context["r13"])
        self.context.setConcreteRegisterValue(self.context.registers.r14, context["r14"])
        self.context.setConcreteRegisterValue(self.context.registers.r15, context["r15"])
        self.context.setConcreteRegisterValue(self.context.registers.rip, context["rip"])
        self.context.setConcreteRegisterValue(self.context.registers.eflags, context["rflags"])
        self.context.setConcreteRegisterValue(self.context.registers.cr0, context["cr0"])
        self.context.setConcreteRegisterValue(self.context.registers.cr3, context["cr3"])
        self.context.setConcreteRegisterValue(self.context.registers.cr4, context["cr4"])
        self.context.setConcreteRegisterValue(self.context.registers.cr8, context["cr8"])
        self.context.setConcreteRegisterValue(self.context.registers.gs, context["gs_base"])

    def get_opcode(self, pc):
        opcode = self.context.getConcreteMemoryAreaValue(pc, 16)
        return opcode

    def get_next_pc(self, instruction):
        rip = self.context.getRegisterAst(self.context.registers.rip).evaluate()
        return rip

    def set_memory_range(self, address, data):
        for index, byte in enumerate(data):
            self.context.setConcreteMemoryValue(address + index, ord(byte))

    def emulate_instr(self, pc):
        opcode = self.get_opcode(pc)

        instruction = triton.Instruction()
        instruction.setOpcode(opcode)
        instruction.setAddress(pc)

        opcode = instruction.getOpcode()
        if opcode == "\x00" * len(opcode):
            print("got 0s, emulation probably diverged, aborting")
            return

        try:
            self.context.processing(instruction)
        except TypeError:
            print("error processing %s" % (opcode.encode("hex")))
            return

        return instruction

    # This function returns a set of new inputs based on the last trace.
    def get_new_inputs(self):
        # Set of new inputs
        inputs = list()

        # Get path constraints from the last execution
        pco = self.context.getPathConstraints()

        # Get the astContext
        astCtxt = self.context.getAstContext()

        # We start with any input. T (Top)
        previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())

        # Go through the path constraints
        for pc in pco:
            # If there is a condition
            if pc.isMultipleBranches():
                # Get all branches
                branches = pc.getBranchConstraints()
                for branch in branches:
                    # Get the constraint of the branch which has been not taken
                    if not branch['isTaken']:
                        # Ask for a model
                        models = self.context.getModel(astCtxt.land([previousConstraints, branch['constraint']]))
                        seed = dict()
                        for k, v in list(models.items()):
                            # Get the symbolic variable assigned to the model
                            symVar = self.context.getSymbolicVariable(k)
                            # Save the new input as seed.
                            seed.update({symVar.getOrigin(): v.getValue()})
                        if seed:
                            inputs.append(seed)

            # Update the previous constraints with true branch to keep a good path.
            previousConstraints = astCtxt.land([previousConstraints, pc.getTakenPredicate()])

        # Clear the path constraints to be clean at the next execution.
        self.context.clearPathConstraints()

        return inputs

    def symbolize_inputs(self, seed):
        # Clean symbolic state
        self.context.concretizeAllRegister()
        self.context.concretizeAllMemory()
        for address, value in list(seed.items()):
            self.context.setConcreteMemoryValue(address, value)
            self.context.symbolizeMemory(triton.MemoryAccess(address, triton.CPUSIZE.BYTE))
            # self.context.symbolizeMemory(triton.MemoryAccess(address + 1, triton.CPUSIZE.BYTE))
        return


def init_context(emulator, trace):
    for address in trace.iter_pages():
        data = trace.load_page(address)
        emulator.set_memory_range(address, data)


def display_seed(seed):
    for address, value in seed.items():
        print("%016x: %02x" % (address, value))


class Input(object):

    def __init__(self, address, data):
        self.address = address
        self.size = len(data)
        self.data = data

    def display(self):
        data = []
        for address, value in sorted(self.data.items()):
            if address != self.address and address % 0x10 == 0:
                data.append("\n")
            byte = "%02x " % (value)
            data.append(colorama.Fore.WHITE + byte + colorama.Fore.RESET)

        print("".join(data))

    def diff(self, seed):
        data = []
        for address, value in sorted(self.data.items()):
            if address != self.address and address % 0x10 == 0:
                data.append("\n")
            if address in seed.keys():
                seed_value = seed[address]
                byte = "%02x " % (seed_value)
                data.append(colorama.Fore.RED + byte + colorama.Fore.RESET)
            else:
                byte = "%02x " % (value)
                data.append(colorama.Fore.WHITE + byte + colorama.Fore.RESET)

        print("".join(data))


@click.command()
@click.argument("trace")
def cli(trace):
    colorama.init()

    trace = FileTrace(trace)
    emulator = TritonEmulator()

    initial_context = trace.get_initial_context()

    addresses = trace.trace["addresses"]

    init_context(emulator, trace)

    address = initial_context["rdx"]
    data = emulator.context.getConcreteMemoryAreaValue(address, 0x70)
    worklist = []
    generated_inputs = []

    item = {}
    for index, b in enumerate(data):
        item[address + index] = ord(b)

    initial_input = Input(address, item)
    worklist.append(item)

    print("initial input @ %016x" % (address))
    initial_input.display()
    print("")

    while worklist:
        print("--> worklist has %d item(s)" % (len(worklist)))
        print("")

        counter = 0
        pc = initial_context["rip"]

        print("initializing triton context")
        emulator.set_context(initial_context)
        init_context(emulator, trace)
        print("")

        seed = worklist[0]

        emulator.symbolize_inputs(seed)

        print("starting emulation")
        while pc != initial_context["return_address"]:
            instruction = emulator.emulate_instr(pc)
            if instruction is None:
                break
            pc = emulator.get_next_pc(instruction)

            address = addresses[counter]
            if address != pc:
                print("diverged: got %x expected %x" % (pc, address))
                break

            counter += 1

        print("emulated %d instructions" % (counter))
        print("")

        print("checking for new inputs")
        generated_inputs += [dict(seed)]
        del worklist[0]

        new_inputs = emulator.get_new_inputs()
        count = 0
        for inputs in new_inputs:
            if inputs not in generated_inputs and inputs not in worklist:
                print("got new input")
                new_seed = dict(inputs)
                initial_input.diff(new_seed)
                print("")
                worklist += [new_seed]
                count += 1

        print("got %d new input(s)" % (count))

        emulator.context.reset()
        print("")

    print("generated %d new input(s)" % (len(generated_inputs)))
    for seed in generated_inputs[1:]:
        initial_input.diff(seed)
        print("")


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
