"""Bounded production FD raw-ingredient query; no mock provider or private flag."""
import json
import os
import subprocess
import sys
import tempfile
HELPER = sys.argv[1]
REQUEST = dict(kind="private_frame_operands", call_seq=1, entry_seq=2,
               function="App+0x2000", target_modules=["App"])
TRACE = """[App] 0x400000!0x0 bl #0x401000; x0=0x2a
[App] 0x401000!0x1000 bl #0x402000; x0=0x2a sp=0x8000
[App] 0x402000!0x2000 sub sp, sp, #0x10; sp=0x8000 -> sp=0x7ff0
[App] 0x402004!0x2004 str x0, [sp]; x0=0x2a sp=0x7ff0 mem_w=0x7ff0
[App] 0x402008!0x2008 ldr x0, [sp]; sp=0x7ff0 mem_r=0x7ff0 -> x0=0x2a
[App] 0x40200c!0x200c add sp, sp, #0x10; sp=0x7ff0 -> sp=0x8000
[App] 0x402010!0x2010 ret; x0=0x2a lr=0x401004 sp=0x8000
[App] 0x401004!0x1004 ret; x0=0x2a lr=0x400004 sp=0x8000
[App] 0x400004!0x4 nop; x0=0x2a
"""
def invoke(trace=TRACE, request=REQUEST, success=True):
    with tempfile.TemporaryDirectory(prefix="private-operands-") as d:
        path = os.path.join(d, "trace.log")
        with open(path, "w") as f: f.write(trace)
        with open(path, "rb") as f:
            r = subprocess.run([HELPER, "--function-facts-helper", "--trace-fd", str(f.fileno())], input=(request if isinstance(request,str) else json.dumps(request)).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(f.fileno(),))
        if not success:
            assert r.returncode != 0 and not r.stdout, r.stdout
            return
        assert r.returncode == 0, r.stderr.decode()
        return json.loads(r.stdout)
p = invoke()
assert p["coverage"]["complete"] and not p["gaps"], p
assert p["coverage"]["scanned_lines"] == 5 and p["coverage"]["access_count"] == 2
assert [i["seq"] for i in p["instructions"]] == list(range(2,7))
assert all(i["owner_entry_seq"] == 2 for i in p["instructions"])
assert [i["raw_line"] for i in p["instructions"]] == TRACE.splitlines()[2:7]
assert p["instructions"][1]["memory"]["bytes"] == [42,0,0,0,0,0,0,0]
assert p["instructions"][2]["memory"]["bytes"] == [42,0,0,0,0,0,0,0]
assert {r["role"] for r in p["instructions"][-1]["roles"]} == {"return_value","return_target","stack_state"}
# Mechanical coverage is NOT no-escape: SP-derived store-data and return remain exposed.
escape = TRACE.replace("str x0, [sp]; x0=0x2a sp=0x7ff0 mem_w=0x7ff0", "mov x9, sp; sp=0x7ff0 -> x9=0x7ff0\n[App] 0x402006!0x2006 str x9, [x1]; x9=0x7ff0 x1=0x7000 mem_w=0x7000")
p = invoke(escape)
assert p["coverage"]["complete"], p
store = p["instructions"][2]
assert any(r["role"] == "store_data" and r["pre_value"] == "0x7ff0" for r in store["roles"])
assert store["memory"]["address"] == "0x7000"
returned = TRACE.replace("ldr x0, [sp]; sp=0x7ff0 mem_r=0x7ff0 -> x0=0x2a", "mov x0, sp; sp=0x7ff0 -> x0=0x7ff0").replace("ret; x0=0x2a lr=0x401004", "ret; x0=0x7ff0 lr=0x401004")
p = invoke(returned)
assert p["coverage"]["complete"] and p["instructions"][-1]["roles"][0]["pre_value"] == "0x7ff0", p
for old,new in [
    ("str x0, [sp]; x0=0x2a", "str x0, [sp];"),
    ("ldr x0, [sp]", "ldr w0, [sp]"),
    ("ldr x0, [sp]", "mystery x0, [sp]"),
    ("add sp, sp, #0x10", "add sp, sp, x1"),
    ("-> sp=0x8000", "-> sp=0x8010"),
    ("lr=0x401004 ", ""),
]:
    p = invoke(TRACE.replace(old,new))
    assert not p["coverage"]["complete"] and p["gaps"], p
p = invoke(TRACE.replace("str x0, [sp]; x0=0x2a", "str x0, [sp];"))
assert p["instructions"][1]["memory"]["bytes"] == [None]*8, p
# Raw special lines are represented, never dropped or converted to NOP.
p = invoke(TRACE.replace("[App] 0x402008", "special raw observation\n[App] 0x402008"))
assert not p["coverage"]["complete"] and p["coverage"]["scanned_lines"] == 6, p
assert p["instructions"][2]["raw_line"] == "special raw observation" and p["instructions"][2]["mnemonic"] is None, p
# A nested call with inconsistent return boundary is rejected before raw coverage.
child = TRACE.replace("[App] 0x402008", "[App] 0x402006!0x2006 bl #0x403000; sp=0x7ff0\n[App] 0x403000!0x3000 ret; lr=0x402008 sp=0x7ff0\n[App] 0x402008")
invoke(child, success=False)
for request in [dict(REQUEST, entry_seq=3), dict(REQUEST, function="App+0x999"), dict(REQUEST, extra=True), dict(REQUEST, slot_ranges=[]), dict(REQUEST, kind="unknown"), dict(REQUEST,target_modules=["App","App"])]:
    invoke(request=request,success=False)
invoke(request=json.dumps(REQUEST)[:-1]+',"kind":"private_frame_operands"}',success=False)
print("real FD private ingredients passed: all seqs/store-pre/load-post/SP restore; store-data and return escape exposed, not permitted; unknown values/width/ALU/dynamic SP/strict protocol rejected")
