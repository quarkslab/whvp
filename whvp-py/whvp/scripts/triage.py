
import os
import json
import itertools
import shutil
import hashlib

import click

import whvp

from whvp.snapshot import RpycSnapshot, DumpSnapshot


@click.command()
@click.argument("crashes")
@click.argument("output")
@click.option("--snapshot", default="localhost:18861", show_default=True)
@click.option("--limit", default=50, type=int)
def cli(crashes, output, snapshot, limit):
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

    os.makedirs(output, exist_ok=True)

    traces_dir = os.path.join(output, "traces")
    os.makedirs(traces_dir, exist_ok=True)

    buckets_dir = os.path.join(output, "buckets")
    os.makedirs(buckets_dir, exist_ok=True)

    coverages = {}

    files = [crash for crash in os.listdir(crashes) if crash.endswith(".bin")]
    whvp.log(F"loaded {len(files)} crash(es)")
    whvp.log(F"gathering coverage")
    for index, f in enumerate(files):
        coverage_path = os.path.join(traces_dir, f + ".trace.json")
        if os.path.exists(coverage_path):
            whvp.log(F"coverage exists for {f}, loading from file")
            with open(coverage_path, "r") as fp:
                coverage = json.load(fp)
        else:
            whvp.log(F"doing coverage for {f}")
            whvp.log("replaying input")
            replay = os.path.join(crashes, f)
            with open(replay, "rb") as fp:
                replay_data = fp.read()

            path = os.path.splitext(replay)[0] + ".json"
            with open(path, "r") as fp:
                replay_params = json.load(fp)

            tracer.set_initial_context(context)
            params["limit"] = 0
            params["coverage"] = "no"
            params["save_context"] = False
            params["save_instructions"] = False

            whvp.log("first run to map memory")
            trace = tracer.run(params)
            tracer.restore_snapshot()

            tracer.write_virtual_memory(replay_params["input"], replay_data)

            params["limit"] = 0
            params["coverage"] = "instrs"
            params["save_context"] = False
            params["save_instructions"] = False

            whvp.log("second run to replay crash")
            tracer.set_initial_context(context)
            trace = tracer.run(params)
            tracer.restore_snapshot()

            coverage = trace.get_coverage()
            seen = trace.get_unique_addresses()
            status = trace.get_status()
            time = trace.get_elapsed_time()
            whvp.log(F"executed {len(coverage)} instruction(s), {len(seen)} were unique in {time} ({status})")

            whvp.log(F"saving trace to {coverage_path}")
            trace.save(coverage_path)

            with open(coverage_path, "r") as fp:
                coverage = json.load(fp)

        coverages[f] = coverage

    duplicates = {}
    if len(files) >= 1:
        f = files[0]
        duplicates[f] = set([])

    combinations = list(itertools.combinations(files, 2))
    whvp.log(F"{len(combinations)} comparaison(s) to do")
    for index, (f, g) in enumerate(combinations):
        cov_f = coverages[f]["coverage"]
        cov_g = coverages[g]["coverage"]

        if cov_f[-limit:] != cov_g[-limit:]:
            continue

        if f not in duplicates and g not in duplicates:
            found = None
            for k, v in duplicates.items():
                if f in v or g in v:
                    found = k
            if found is None:
                duplicates[f] = set([])
                duplicates[f].add(g)
            else:
                duplicates[found].add(f)
                duplicates[found].add(g)

        elif f in duplicates and g not in duplicates:
            l = duplicates[f]
            l.add(g)
        elif f not in duplicates and g in duplicates:
            l = duplicates[g]
            l.add(f)
        else:
            duplicates[f].add(g)

    whvp.log(F"triaged {len(files)} crash(es)")
    whvp.log(F"found {len(duplicates)} unique crash(es)")
    for bucket, duplicates in duplicates.items():
        whvp.log(F"{bucket} has {len(duplicates)} duplicate(s)")

        m = hashlib.sha1()
        for (address, context) in coverages[bucket]["coverage"][-limit:]:
            data = F"{address:016x}"
            m.update(bytes(data, encoding="utf-8"))

        filename = m.hexdigest()

        bucket_path = os.path.join(buckets_dir, filename)
        os.makedirs(bucket_path, exist_ok=True)

        src = os.path.join(crashes, bucket)
        shutil.copy(src, bucket_path)

        src = os.path.join(crashes, os.path.splitext(bucket)[0] + ".json")
        shutil.copy(src, bucket_path)

        for d in duplicates:
            src = os.path.join(crashes, d)
            shutil.copy(src, bucket_path)

            src = os.path.join(crashes, os.path.splitext(d)[0] + ".json")
            shutil.copy(src, bucket_path)


def entrypoint():
    cli()


if __name__ == "__main__":
    entrypoint()
