
import re

import click

import rpyc

import pykd


class System(object):

    IA32_SYSENTER_CS = 0x174
    IA32_SYSENTER_ESP = 0x175
    IA32_SYSENTER_EIP = 0x176

    IA32_EFER = 0xC0000080
    STAR = 0xC0000081
    LSTAR = 0xC0000082
    CSTAR = 0xC0000083
    SFMASK = 0xC0000084

    FS_BASE = 0xC0000100
    GS_BASE = 0xC0000101
    KERNEL_GS_BASE = 0xC0000102

    PTE_REGEXP = re.compile(r"pfn\s+([0-9a-f]+)")

    def __init__(self):
        pykd.setSymbolPath(r"srv*c:\symbols*https://msdl.microsoft.com/download/symbols")

    def get_reg(self, name):
        return pykd.reg(name)

    def read_virtual_address(self, address, size):
        return bytes(pykd.loadBytes(address, size))

    def read_physical_address(self, address, size):
        return bytes(pykd.loadBytes(address, size, True))

    def read_qword(self, address):
        return pykd.ptrQWord(address)

    def get_symbol(self, address):
        return pykd.findSymbolAndDisp(address)

    def get_formatted_symbol(self, address):
        try:
            symbol = self.get_symbol(address)
            return F"{symbol[0]}!{symbol[1]}+0x{symbol[2]:x}"
        except Exception:
            return None

    def get_address(self, name):
        return pykd.getOffset(name)

    def get_kpcr(self):
        return self.read_msr(self.GS_BASE)

    def get_teb(self):
        return self.read_msr(self.FS_BASE)

    def get_kernel_gs_base(self):
        return self.read_msr(self.KERNEL_GS_BASE)

    def read_msr(self, msr):
        return pykd.rdmsr(msr)

    def get_ptes(self, addr):
        ptes = []
        data = pykd.dbgCommand(F"!pte {addr:x}").splitlines()
        for line in data:
            for m in self.PTE_REGEXP.finditer(line):
                ptes.append(int(m.group(1), 16))
        return ptes

    def get_module(self, address):
        return pykd.module(address)

    def expr(self, expr):
        return pykd.expr(expr)

    def get_segment(self, segment):
        selector = self.get_reg(segment)
        output = pykd.dbgCommand("dg %x" % (selector))
        line = output.splitlines()[-1]
        tokens = line.split()
        segment = {}
        segment["selector"] = pykd.expr(tokens[0])
        segment["base"] = pykd.expr(tokens[1])
        segment["limit"] = pykd.expr(tokens[2])
        segment["flags"] = pykd.expr(tokens[11])
        return segment


class PyKDService(rpyc.Service):
    def on_connect(self, conn):
        print("got new connection")
        self.system = System()

    def on_disconnect(self, conn):
        print("client disconnected")
        self.system = None

    def exposed_get_reg(self, name):
        return self.system.get_reg(name)

    def exposed_read_physical_address(self, address, size):
        return self.system.read_physical_address(address, size)

    def exposed_read_qword(self, address):
        return self.system.read_qword(address)

    def exposed_read_page(self, address, physical=False):
        return self.system.read_page(address, physical=physical)

    def exposed_get_symbol(self, address):
        return self.system.get_symbol(address)

    def exposed_get_formatted_symbol(self, address):
        return self.system.get_formatted_symbol(address)

    def exposed_get_modules(self):
        return self.system.module_manager.get_modules()

    def exposed_add_module(self, address):
        self.system.module_manager.add_module(address)

    def exposed_get_address(self, name):
        return self.system.get_address(name)

    def exposed_get_module(self, address):
        return self.system.get_module(address)

    def exposed_expr(self, expr):
        return self.system.expr(expr)

    def exposed_get_segment(self, segment):
        return self.system.get_segment(segment)

    def exposed_read_msr(self, msr):
        return self.system.read_msr(msr)

    @property
    def exposed_IA32_EFER(self):
        return self.system.IA32_EFER

    @property
    def exposed_FS_BASE(self):
        return self.system.FS_BASE

    @property
    def exposed_GS_BASE(self):
        return self.system.GS_BASE

    @property
    def exposed_KERNEL_GS_BASE(self):
        return self.system.KERNEL_GS_BASE

    @property
    def exposed_IA32_SYSENTER_CS(self):
        return self.system.IA32_SYSENTER_CS

    @property
    def exposed_IA32_SYSENTER_ESP(self):
        return self.system.IA32_SYSENTER_ESP

    @property
    def exposed_IA32_SYSENTER_EIP(self):
        return self.system.IA32_SYSENTER_EIP

    @property
    def exposed_STAR(self):
        return self.system.STAR

    @property
    def exposed_LSTAR(self):
        return self.system.LSTAR

    @property
    def exposed_CSTAR(self):
        return self.system.CSTAR


@click.command()
@click.argument("context", required=False)
def cli(context):
    while 42:
        # FIXME: multithreaded server hangs pykd
        print("running rpyc server")
        from rpyc.utils.server import OneShotServer
        t = OneShotServer(PyKDService, port=18861, protocol_config={"allow_all_attrs": True})
        t.start()


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
