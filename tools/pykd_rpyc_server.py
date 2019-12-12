
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

    def exposed_get_kpcr(self):
        return self.system.read_msr(self.system.GS_BASE)

    def exposed_get_teb(self):
        return self.system.read_msr(self.system.FS_BASE)

    def exposed_get_efer(self):
        return self.system.read_msr(self.system.IA32_EFER)

    def exposed_get_kernel_gs_base(self):
        return self.system.read_msr(self.system.KERNEL_GS_BASE)

    def exposed_get_sysenter_cs(self):
        return self.system.read_msr(self.system.IA32_SYSENTER_CS)

    def exposed_get_sysenter_esp(self):
        return self.system.read_msr(self.system.IA32_SYSENTER_ESP)

    def exposed_get_sysenter_eip(self):
        return self.system.read_msr(self.system.IA32_SYSENTER_EIP)

    def exposed_get_star(self):
        return self.system.read_msr(self.system.STAR)

    def exposed_get_lstar(self):
        return self.system.read_msr(self.system.LSTAR)

    def exposed_get_cstar(self):
        return self.system.read_msr(self.system.CSTAR)

    def exposed_get_sfmask(self):
        return self.system.read_msr(self.system.SFMASK)

    def exposed_read_page(self, address, physical=False):
        return self.system.read_page(address, physical=physical)

    def exposed_get_symbol(self, address):
        return self.system.get_symbol(address)

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
