
import os
import json

import rpyc
import pykd

import whvp


class RpycSnapshot(object):

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
        context["efer"] = system.read_msr(system.IA32_EFER)

        context["cs"] = dict(system.get_segment("cs"))
        # FIXME: flags are wrong
        context["cs"]["flags"] |= 0x2000

        context["ss"] = dict(system.get_segment("ss"))
        context["ds"] = dict(system.get_segment("ds"))
        context["es"] = dict(system.get_segment("es"))

        context["fs"] = dict(system.get_segment("fs"))
        context["gs"] = dict(system.get_segment("gs"))

        context["fs_base"] = system.read_msr(system.FS_BASE)
        context["gs_base"] = system.read_msr(system.GS_BASE)
        context["kernel_gs_base"] = system.read_msr(system.KERNEL_GS_BASE)

        context["sysenter_cs"] = system.read_msr(system.IA32_SYSENTER_CS)
        context["sysenter_esp"] = system.read_msr(system.IA32_SYSENTER_ESP)
        context["sysenter_eip"] = system.read_msr(system.IA32_SYSENTER_EIP)

        context["star"] = system.read_msr(system.STAR)
        context["lstar"] = system.read_msr(system.LSTAR)
        context["cstar"] = system.read_msr(system.CSTAR)

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

        return context

    def get_params(self):
        system = self.system
        params = {}
        params["return_address"] = system.read_qword(system.get_reg("rsp"))
        params["excluded_addresses"] = {}
        params["excluded_addresses"]["nt!KeBugCheck"] = system.get_address("nt!KeBugCheck")
        params["excluded_addresses"]["nt!KeBugCheck2"] = system.get_address("nt!KeBugCheck2")
        params["excluded_addresses"]["nt!KeBugCheckEx"] = system.get_address("nt!KeBugCheckEx")

        return params

    def memory_access_callback(self, gpa, gva):
        base = gpa & ~0xfff
        data = self.system.read_physical_address(base, 0x1000)
        return bytes(data)


class DumpSnapshot(object):

    def __init__(self, path):
        self.path = path

        path = os.path.join(self.path, "context.json")
        with open(path, "r") as fp:
            self.context = json.load(fp)

        whvp.log("loading dump")
        path = os.path.join(self.path, "mem.dmp")
        pykd.loadDump(path)

    def memory_access_callback(self, gpa, gva):
        return bytes(pykd.loadBytes(gpa, 0x1000, True))

    def get_initial_context(self):
        return self.context

    def get_params(self):
        path = os.path.join(self.path, "params.json")
        with open(path, "r") as fp:
            params = json.load(fp)

        return params

