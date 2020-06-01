
import os
import json
import uuid

import click
import whvp

from whvp.snapshot import RpycSnapshot, DumpSnapshot


def handle_resume(ctx, param, value):
    if value is None:
        return

    try:
        path = os.path.join(value, "params.json")
        with open(path, "r") as fp:
            params = json.load(fp)

    except Exception:
        raise click.BadParameter("invalid resume directory")

    ctx.params["input"] = params["input"]
    ctx.params["input_size"] = params["input_size"]
    ctx.params["workdir"] = value

    return value


def from_param_callback(ctx, param, value):
    if value is None:
        return ctx.params.get(param.name)
    else:
        return value


@click.command()
@click.argument("context", required=False)
@click.option("--snapshot", "snapshot_str", default="localhost:18861", show_default=True)
@click.option("--coverage", type=click.Choice(["no", "hit", "instrs"]), default="hit", show_default=True)
@click.option("--max-time", type=int, default=0, show_default=True)
@click.option("--max-iterations", type=int, default=0, show_default=True)
@click.option("--display-delay", type=int, default=1, show_default=True)
@click.option("--stop-on-crash", is_flag=True, show_default=True)
@click.option("--resume", is_eager=True, callback=handle_resume)
@click.option("--input", callback=from_param_callback)
@click.option("--input-size", callback=from_param_callback)
@click.option("--workdir", callback=from_param_callback)
def cli(context, snapshot_str, coverage, max_time, max_iterations, display_delay,
        stop_on_crash, resume, input, input_size, workdir):

    whvp.init_log()

    if ":" in snapshot_str:
        hostname, port = snapshot_str.split(":")
        snapshot = RpycSnapshot(hostname, int(port))
    else:
        path = snapshot_str
        snapshot = DumpSnapshot(path)

    context = snapshot.get_initial_context()

    tracer = whvp.Tracer(snapshot.memory_access_callback)

    if resume is None:
        os.makedirs(workdir, exist_ok=True)
        guid = str(uuid.uuid4())
        fuzzer_workdir = os.path.join(workdir, guid)
        os.makedirs(fuzzer_workdir)

        input = int(input, 16)
        input_size = int(input_size, 16)

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
        "input": input,
        "input_size": input_size,
        "stop_on_crash": stop_on_crash,
        "display_delay": display_delay,
        "snapshot": snapshot_str
    }

    path = os.path.join(fuzzer_workdir, "params.json")
    with open(path, "w") as fp:
        json.dump(fuzz_params, fp, indent=2)

    fuzzer.run(tracer, context, trace_params, fuzz_params)


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
