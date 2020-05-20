
import os
import json
import base64

import pytest

import whvp


@pytest.fixture
def logger():
    whvp.init_log()


def test_basic_trace():
    with open(os.path.join("tests", "RtlInitUnicodeString.json"), "r") as fp:
        context = json.load(fp)

    regs = context["regs"]
    regs["rflags"] = 0x40246
    regs["efer"] = context["efer"]

    for r in ["cs", "ss", "ds", "es", "fs", "gs"]:
        regs[r] = {
            "selector": regs[r],
            "base": 0,
            "limit": 0,
            "flags": 0,
        }

    def callback(gpa, gva):
        pfn = gpa >> 12
        print(F"writing pfn {pfn:x}")

        data = context["pfn"].get(str(pfn))
        if data:
            data = base64.b64decode(data)
            return data
        else:
            print("unknown pfn")

    tracer = whvp.Tracer(callback)

    tracer.set_initial_context(regs)

    params = {"limit": 25,
              "coverage": "instrs",
              "save_context": False,
              "save_instructions": False,
              "excluded_addresses": {
              },
              "return_address": context["return_address"]}

    result = tracer.run(params)
    print(result)
    coverage = result.get_coverage()
    print(coverage)
    assert len(coverage) == 5
    assert len(coverage[0]) == 1
    instructions = result.get_instructions()
    assert len(instructions) == 0

    tracer.set_initial_context(regs)
    params["save_context"] = True

    result = tracer.run(params)
    print(result)
    coverage = result.get_coverage()
    print(coverage)
    assert len(coverage) == 5
    assert len(coverage[0]) == 18
    instructions = result.get_instructions()
    assert len(instructions) == 0

    tracer.set_initial_context(regs)
    params["save_instructions"] = True

    result = tracer.run(params)
    print(result)
    instructions = result.get_instructions()
    print(instructions)
    assert len(instructions) == 5


def test_complex_trace():
    with open(os.path.join("tests", "sdb", "context.json"), "r") as fp:
        context = json.load(fp)

    for r in ["cs", "ss", "ds", "es", "fs", "gs"]:
        context[r] = {
            "selector": context[r],
            "base": 0,
            "limit": 0,
            "flags": 0,
        }

    def callback(gpa, gva):
        path = os.path.join("tests", "sdb", "mem", F"{gpa:016x}.bin")
        if os.path.exists(path):
            with open(path, "rb") as fp:
                data = fp.read()

            if data:
                return data
            else:
                print("no data")
        else:
            print(F"missing file {path}")

    tracer = whvp.Tracer(callback)
    # context["rflags"] |= 0x100

    tracer.set_initial_context(context)

    params = {"coverage": "no",
              "limit": 0,
              "save_context": False,
              "save_instructions": False,
              "excluded_addresses": {
              },
              "return_address": context["return_address"]}

    result = tracer.run(params)
    print(result)
    coverage = result.get_coverage()

    assert len(coverage) == 1

    tracer.set_initial_context(context)
    tracer.restore_snapshot()

    params["coverage"] = "instrs"

    result = tracer.run(params)
    print(result)
    coverage = result.get_coverage()

    assert len(coverage) == 59120


def test_complex_trace2():
    with open(os.path.join("tests", "sdb", "context.json"), "r") as fp:
        context = json.load(fp)

    for r in ["cs", "ss", "ds", "es", "fs", "gs"]:
        context[r] = {
            "selector": context[r],
            "base": 0,
            "limit": 0,
            "flags": 0,
        }

    def callback(gpa, gva):
        path = os.path.join("tests", "sdb", "mem", F"{gpa:016x}.bin")
        if os.path.exists(path):
            with open(path, "rb") as fp:
                data = fp.read()

            if data:
                return data
            else:
                print("no data")
        else:
            print(F"missing file {path}")

    tracer = whvp.Tracer(callback)

    tracer.set_initial_context(context)

    params = {"coverage": "hit",
              "limit": 0,
              "excluded_addresses": {
              },
              "save_context": False,
              "save_instructions": False,
              "return_address": context["return_address"]}

    result = tracer.run(params)
    print(result)
    coverage = result.get_coverage()
    seen = result.get_unique_addresses()
    status = result.get_status()
    # FIXME: check with seen
    assert status == "Success"
    assert len(coverage) == len(seen)

