
import os
import uuid

import click
import whvp

from whvp.snapshot import RpycSnapshot, DumpSnapshot


@click.command()
@click.argument("context", required=False)
@click.option("--snapshot", default="localhost:18861", show_default=True)
@click.option("--coverage", type=click.Choice(["no", "hit", "instrs"]), default="hit", show_default=True)
@click.option("--max-time", type=int, default=0, show_default=True)
@click.option("--max-iterations", type=int, default=0, show_default=True)
@click.option("--display-delay", type=int, default=1, show_default=True)
@click.option("--stop-on-crash", is_flag=True, show_default=True)
@click.option("--input", required=True)
@click.option("--input-size", required=True)
@click.option("--workdir", required=True)
@click.option("--resume")
def cli(context, snapshot, coverage, max_time, max_iterations, display_delay,
        stop_on_crash, input, input_size, workdir, resume):

    # FIXME: resuming should only require workdir directory
    whvp.init_log()

    if ":" in snapshot:
        hostname, port = snapshot.split(":")
        snapshot = RpycSnapshot(hostname, int(port))
    else:
        path = snapshot
        snapshot = DumpSnapshot(path)

    context = snapshot.get_initial_context()

    tracer = whvp.Tracer(snapshot.memory_access_callback)

    # FIXME: improve this
    os.makedirs(workdir, exist_ok=True)
    if resume is None:
        guid = str(uuid.uuid4())
        fuzzer_workdir = os.path.join(workdir, guid)
        os.makedirs(fuzzer_workdir)
    else:
        fuzzer_workdir = resume

    whvp.log(F"fuzzer workdir is {fuzzer_workdir}")

    crashes_path = os.path.join(fuzzer_workdir, "crashes")
    os.makedirs(crashes_path, exist_ok=True)

    corpus_path = os.path.join(fuzzer_workdir, "corpus")
    os.makedirs(corpus_path, exist_ok=True)

    fuzzer = whvp.Fuzzer(fuzzer_workdir)

    trace_params = snapshot.get_params()

    trace_params["limit"] = 0
    trace_params["coverage"] = coverage
    trace_params["save_context"] = False
    trace_params["save_instructions"] = False

    fuzz_params = {
        "max_iterations": max_iterations,
        "max_time": max_time,
        "input": int(input, 16),
        "input_size": int(input_size, 16),
        "stop_on_crash": stop_on_crash,
        "display_delay": display_delay
    }
    # FIXME: save params in workdir for replay and resuming

    fuzzer.run(tracer, context, trace_params, fuzz_params)


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
