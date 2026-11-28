import ctypes,hashlib,json,os,pathlib,shutil,subprocess,time
root=pathlib.Path("/mnt/trames-output")
current=root/"jit-control-source"
baseline=root/"jit-control-baseline-source"
examples=["compatibility-category","execution-entry"]
meta={"baseline_runtime":"bf8e801e09b43d9d04467cf2ca14711811da2d6a","rustc":subprocess.check_output(["rustc","-Vv"],text=True),"page_size":os.sysconf("SC_PAGESIZE"),"cpu_affinity":0,"samples":32,"warmup":8,"order":["before","after","after","before","before","after","after","before"],"binaries":{},"harness_sha256":{},"workloads":["control-integer","control-scalar-memory","svc-only","svc-round-trip","svc-continuation"]}
libc=ctypes.CDLL(None);libc.getauxval.restype=ctypes.c_ulong
meta["hwcap"]=hex(libc.getauxval(16));meta["hwcap2"]=hex(libc.getauxval(26))
for name in examples:
    source=current/("crates/trames-jit/examples/"+name+".rs")
    shutil.copyfile(source,baseline/("crates/trames-jit/examples/"+name+".rs"))
    meta["harness_sha256"][name]=hashlib.sha256(source.read_bytes()).hexdigest()
for label,source in [("before",baseline),("after",current)]:
    env=os.environ.copy();env["CARGO_TARGET_DIR"]=str(root/("jit-control-baseline-target" if label=="before" else "jit-control-linux-target"))
    meta["binaries"][label]={}
    for name in examples:
        build=root/("jit-control-"+label+"-"+name+"-build.jsonl")
        with build.open("w") as out,build.with_suffix(".log").open("w") as err:
            subprocess.run(["cargo","build","--release","--locked","-p","trames-jit","--features","native-aarch64","--example",name,"--message-format=json"],cwd=source,env=env,stdout=out,stderr=err,check=True)
        messages=[json.loads(line) for line in build.read_text().splitlines()]
        artifacts=[m["executable"] for m in messages if m.get("reason")=="compiler-artifact" and m["target"]["name"]==name and m.get("executable")]
        assert len(artifacts)==1
        dest=root/("jit-control-bench-"+label+"-"+name)
        shutil.copy2(artifacts[0],dest)
        meta["binaries"][label][name]={"sha256":hashlib.sha256(dest.read_bytes()).hexdigest(),"source":str(source),"target_dir":env["CARGO_TARGET_DIR"]}
    print("built",label,flush=True)
(root/"jit-control-bench-provenance.json").write_text(json.dumps(meta,indent=2)+"\n")
for workload in meta["workloads"]:
    example="compatibility-category" if workload.startswith("control-") else "execution-entry"
    for index,label in enumerate(meta["order"]):
        env=os.environ.copy();env["TRAMES_BENCH_FILTER"]=workload
        env["TRAMES_BENCH_SAMPLES"]=str(meta["samples"]);env["TRAMES_BENCH_WARMUP"]=str(meta["warmup"])
        env["TRAMES_BENCH_REQUIRE_NATIVE"]="1"
        output=root/("jit-control-bench-"+workload+"-"+str(index)+"-"+label+".jsonl")
        start=time.monotonic()
        with output.open("w") as out: subprocess.run(["taskset","-c","0",str(root/("jit-control-bench-"+label+"-"+example))],env=env,stdout=out,check=True)
        rows=[json.loads(line) for line in output.read_text().splitlines()]
        assert len(rows)==meta["samples"] and all(row["fallback"]==0 for row in rows)
        print("finished",workload,index,label,round(time.monotonic()-start,3),flush=True)
