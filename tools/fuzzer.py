
import os
import time
import json

import click
import rpyc
import whvp


from tracer import Tracer


@click.command()
@click.argument("context", required=False)
@click.option("--connection", type=click.Choice(["rpyc", "local"]), default="rpyc", show_default=True)
@click.option("--connection-params", default="localhost:18861", show_default=True)
@click.option("--coverage", type=click.Choice(["no", "hit", "instrs", "bbl"]), default="instrs", show_default=True)
@click.option("--max-time")
@click.option("--max-iterations")
@click.option("--input", required=True)
@click.option("--input-type", type=click.Choice(["mem", "reg"]), default="mem", show_default=True)
@click.option("--input-size")
def cli(context, connection, connection_params, coverage, max_time, max_iterations, input, input_type, input_size):
    emulator = whvp.Emulator()

    tracer = Tracer(emulator)

    print("connecting to rpyc server")
    tracer.connect()

    print("get initial context")
    context = tracer.get_initial_context()

    rip = context["rip"]
    name = tracer.get_formatted_symbol(rip)
    print(F"fuzzing {name} ({rip:x})")

    fuzzer = whvp.Fuzzer()

    stopping_functions = ["nt!KeYieldProcessorEx",
                "nt!KeBugCheckEx",
                "nt!KiIpiSendRequestEx",
                "nt!KiExceptionDispatch"]

    stopping_addresses = []
    for name in stopping_functions:
        address = tracer.get_address(name)
        if address is not None:
            stopping_addresses.append(address)

    # data: poi(poi(poi(sdbparser!SdbHandle)+8)+8)
    # size: poi(poi(sdbparser!SdbHandle)+8)+0x10)

    input_value = tracer.system.expr(input)
    print(F"input is {input_value:x}")
    input_size = tracer.system.expr(input_size)
    print(F"input size is {input_size:x}")
    return

    params = {
        "coverage_mode": coverage,
        "return_address": context["return_address"],
        "save_context": False,
        "stopping_addresses": stopping_addresses,
        "max_iterations": max_iterations,
        "max_time": max_time,
        "input": input,
        "input_type": input_type,
        "input_size": input_size
    }

    print("running fuzzer")
    fuzzer.run(emulator, context, params, tracer.memory_access_callback)


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
