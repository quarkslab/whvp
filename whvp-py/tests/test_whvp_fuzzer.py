import os
import json

import pytest

import whvp


@pytest.fixture
def logger():
    whvp.init_log()


def test_fuzzer(logger):
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

    path = os.path.join("tests", "fuzzing", "corpus")
    os.makedirs(path, exist_ok=True)

    fuzzer = whvp.Fuzzer(os.path.join("tests", "fuzzing"))

    trace_params = {
        "coverage": "hit",
        "save_context": False,
        "save_instructions": False,
        "limit": 0,
        "excluded_addresses": {
                    "a": 18446735301117361296,
                    "b": 18446735301119068320,
                    "c": 18446735301118187352,
                    "d": 18446735301120002752,
                    "e": 18446735301127018072,
                    "f": 18446735301120046400,
                    "g": 18446735301119141248
        },
        "return_address": context["return_address"]
    }

    fuzz_params = {
        "max_iterations": 1,
        "max_time": 0,
        "input": 18446613794899639584,
        "input_size": 96,
        "stop_on_crash": True,
        "display_delay": 1
    }

    fuzzer.run(tracer, context, trace_params, fuzz_params)


def test_crash():
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

    trace_params = {
        "coverage": "no",
        "save_context": False,
        "save_instructions": False,
        "limit": 0,
        "excluded_addresses": {
                    "a": 18446735301117361296,
                    "b": 18446735301119068320,
                    "c": 18446735301118187352,
                    "d": 18446735301120002752,
                    "e": 18446735301127018072,
                    "f": 18446735301120046400,
                    "g": 18446735301119141248
        },
        "return_address": context["return_address"]
    }

    tracer = whvp.Tracer(callback)
    tracer.set_initial_context(context)

    result = tracer.run(trace_params)

    tracer.set_initial_context(context)
    tracer.restore_snapshot()

    fuzz_params = {
        "max_iterations": 0,
        "max_time": 1,
        "input": 18446613794899639584,
        "input_size": 96,
        "stop_on_crash": True,
        "display_delay": 1
    }

    address = fuzz_params["input"]
    with open(os.path.join("tests", "fuzzing", "crash.bin"), "rb") as fp:
        data = fp.read()

    tracer.write_virtual_memory(address, data)

    result = tracer.run(trace_params)

    print(result)

    status = result.get_status()
    assert status == "ForbiddenAddress"

