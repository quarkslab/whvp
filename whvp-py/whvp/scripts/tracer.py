
import os
import json

import click
import whvp

from whvp import helpers
from whvp.snapshot import RpycSnapshot, DumpSnapshot


@click.command()
@click.option("--snapshot", default="localhost:18861", show_default=True)
@click.option("--coverage", type=click.Choice(["no", "hit", "instrs"]), default="no", show_default=True)
@click.option("--save-context", is_flag=True, show_default=True)
@click.option("--save-instructions", is_flag=True, show_default=True)
@click.option("--save-trace")
@click.option("--replay")
def cli(snapshot, coverage, save_context, save_instructions, save_trace, replay):
    whvp.init_log()

    if ":" in snapshot:
        hostname, port = snapshot.split(":")
        snapshot = RpycSnapshot(hostname, int(port))
    else:
        path = snapshot
        snapshot = DumpSnapshot(path)

    context = snapshot.get_initial_context()
    params = snapshot.get_params()

    tracer = whvp.Tracer(snapshot.memory_access_callback)

    # FIXME: rename to set_context
    tracer.set_initial_context(context)

    params["limit"] = 0
    params["coverage"] = coverage
    params["save_context"] = save_context
    params["save_instructions"] = save_instructions

    whvp.log("running tracer")
    trace = tracer.run(params)

    coverage = trace.get_coverage()
    seen = trace.get_unique_addresses()
    status = trace.get_status()
    time = trace.get_elapsed_time()
    whvp.log(F"executed {len(coverage)} instruction(s), {len(seen)} were unique in {time} ({status})")

    pages = tracer.restore_snapshot()
    whvp.log(F"{pages} page(s) were modified")
    # FIXME: get dirty pages, code pages, data pages

    if replay:
        whvp.log("replaying input")
        with open(replay, "r") as fp:
            replay_params = json.load(fp)

        path = os.path.splitext(replay)[0] + ".bin"
        with open(path, "rb") as fp:
            replay_data = fp.read()

        tracer.set_initial_context(context)
        orig_data = tracer.read_virtual_memory(replay_params["input"], replay_params["input_size"])

        input = helpers.Input(replay_params["input"], orig_data)
        whvp.log("input bytes:")
        print(input.diff(replay_data))

        whvp.log("running tracer with modified input")
        tracer.write_virtual_memory(replay_params["input"], replay_data)
        trace = tracer.run(params)

        coverage = trace.get_coverage()
        seen = trace.get_unique_addresses()
        status = trace.get_status()
        time = trace.get_elapsed_time()
        whvp.log(F"executed {len(coverage)} instruction(s), {len(seen)} were unique in {time} ({status})")

    if save_trace:
        whvp.log(F"saving trace to {save_trace}")
        trace.save(save_trace)


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
