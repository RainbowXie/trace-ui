"""Small production FD-helper store/load/address demonstrations, no fake facts."""
import json
import os
import subprocess
import sys
import tempfile
HELPER = sys.argv[1]
REQUEST = dict(kind="output_slot_uses", call_seq=1, entry_seq=2,
               function="App+0x2000", target_modules=["App"],
               slot_ranges=[dict(address="0x7000", size=8)])
PREFIX = """[App] 0x400000!0x0 bl #0x401000; x0=0x7000
[App] 0x401000!0x1000 bl #0x402000; x0=0x7000
[App] 0x402000!0x2000 str x1, [x0]; x0=0x7000 x1=0x6000 mem_w=0x7000
"""
EXIT = """[App] 0x402100!0x2100 ret; x0=0x7000
"""
CALLER = """[App] 0x401004!0x1004 ldr x2, [x0]; x0=0x7000 mem_r=0x7000 -> x2=0x6000
[App] 0x401008!0x1008 mov x3, x2; x2=0x6000 -> x3=0x6000
[App] 0x40100c!0x100c add x4, x3, #8; x3=0x6000 -> x4=0x6008
[App] 0x401010!0x1010 ldr x5, [x4]; x4=0x6008 mem_r=0x6008 -> x5=0x7
[App] 0x401014!0x1014 ret; x0=0x7000
[App] 0x400004!0x4 nop; x0=0x7000
"""
def invoke(trace, request=REQUEST, success=True):
    with tempfile.TemporaryDirectory(prefix="output-slots-") as d:
        path = os.path.join(d,"trace.log")
        with open(path,"w") as f: f.write(trace)
        with open(path,"rb") as f:
            r = subprocess.run([HELPER,"--function-facts-helper","--trace-fd",str(f.fileno())], input=(request if isinstance(request,str) else json.dumps(request)).encode(), stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(f.fileno(),))
        if not success:
            assert r.returncode and not r.stdout, r.stdout
            return
        assert r.returncode == 0, r.stderr.decode()
        return json.loads(r.stdout)
# Complete finite-window negative: actual known scalar store/load followed
# by a verified immediate definition killing the loaded identity before ret.
scalar_caller = """[App] 0x401004!0x1004 ldr x2, [x0]; x0=0x7000 mem_r=0x7000 -> x2=0x42
[App] 0x401008!0x1008 mov x2, #0; -> x2=0x0
[App] 0x401014!0x1014 ret; x0=0x7000
[App] 0x400004!0x4 nop; x0=0x7000
"""
scalar_prefix = PREFIX.replace("x1=0x6000", "x1=0x42") + "[App] 0x402004!0x2004 mov x1, #0; -> x1=0x0\n"
scalar = invoke(scalar_prefix+EXIT+scalar_caller)
assert scalar["coverage"]["complete"] and not scalar["uses"] and not scalar["gaps"], scalar
direct_source = invoke(PREFIX + "[App] 0x402004!0x2004 ldr x7, [x1]; x1=0x6000 mem_r=0x6000 -> x7=0x3\n" + EXIT + CALLER)
assert not direct_source["coverage"]["complete"] and any(g["kind"] == "untracked_store_source_use" for g in direct_source["gaps"]), direct_source
unknown_usage = scalar_caller.replace("mov x2, #0; -> x2=0x0", "mystery x2; x2=0x42")
unknown_proof = invoke(scalar_prefix+EXIT+unknown_usage)
assert not unknown_proof["coverage"]["complete"] and unknown_proof["gaps"], unknown_proof
p = invoke(PREFIX+EXIT+CALLER)
assert len(p["uses"]) == 1, p
u = p["uses"][0]
assert u["final_output_definition"] and u["chain_complete"] and u["store_seq"] == 2 and u["load_seq"] == 4, u
assert u["store_bytes"] == [0,96,0,0,0,0,0,0] and u["address"] == "0x6008" and u["integer_delta"] == 8, u
assert [s["operation"] for s in u["definition_steps"]] == ["load","mov","add","address"], u
assert not p["coverage"]["complete"], p
partial = "[App] 0x402004!0x2004 str w7, [x0]; x0=0x7000 x7=0x6000 mem_w=0x7000\n"
unknown = "[App] 0x402004!0x2004 mystery x7; x7=0x1\n"
unknown_store = "[App] 0x402004!0x2004 str x7, [x0]; x0=0x7000 mem_w=0x7000\n"
for change in [partial,unknown,unknown_store]:
    p = invoke(PREFIX+change+EXIT+CALLER)
    assert not p["uses"] and p["gaps"] and not p["coverage"]["complete"], p
# Genuine transient use before final scalar replacement is explicitly not final proof.
root_use = """[App] 0x402004!0x2004 ldr x2, [x0]; x0=0x7000 mem_r=0x7000 -> x2=0x6000
[App] 0x402008!0x2008 ldr x5, [x2]; x2=0x6000 mem_r=0x6000 -> x5=0x7
[App] 0x40200c!0x200c str x7, [x0]; x0=0x7000 x7=0x42 mem_w=0x7000
"""
p = invoke(PREFIX+root_use+EXIT+CALLER.replace("-> x2=0x6000","-> x2=0x42"))
assert p["uses"] and not any(u["final_output_definition"] for u in p["uses"]), p
# Loaded value used only as store-data, with coincident address in independent reg.
data_only = CALLER.split("[App] 0x401008")[0]+"""[App] 0x401008!0x1008 str x2, [x9]; x2=0x6000 x9=0x6000 mem_w=0x6000
[App] 0x401014!0x1014 ret; x0=0x7000
[App] 0x400004!0x4 nop; x0=0x7000
"""
escaped = invoke(PREFIX+EXIT+data_only)
assert not escaped["uses"] and not escaped["coverage"]["complete"], escaped
assert any(g["kind"] == "untracked_store_data_escape" for g in escaped["gaps"]), escaped
returned = invoke(scalar_prefix+EXIT+scalar_caller.replace("[App] 0x401008!0x1008 mov x2, #0; -> x2=0x0\n", ""))
assert not returned["coverage"]["complete"], returned
# Real trace_root does not supply confirmed caller ownership.
p = invoke(PREFIX.split("\n",1)[1]+EXIT+CALLER, dict(REQUEST,call_seq=0,entry_seq=1))
assert not p["uses"] and any(g["kind"] == "caller_not_closed" for g in p["gaps"]), p
invoke(PREFIX+EXIT+CALLER,dict(REQUEST,entry_seq=3),False)
invoke(PREFIX+EXIT+CALLER,dict(REQUEST,function="App+0x999"),False)
for change in [dict(REQUEST,unexpected=True),dict(REQUEST,kind="old_output_slots"),dict(REQUEST,slot_ranges=REQUEST["slot_ranges"]*2),dict(REQUEST,slot_ranges=[dict(address="0x7000",size=0)])]: invoke(PREFIX+EXIT+CALLER,change,False)
invoke(PREFIX+EXIT+CALLER,json.dumps(REQUEST)[:-1]+',"kind":"output_slot_uses"}',False)
# Unsigned narrow and pair elements are independent negative obligations.
outer = PREFIX.splitlines()[:2]
def width_trace(store, pre, load, post, source_regs, load_regs):
    lines = outer + [f"[App] 0x402000!0x2000 {store}, [x0]; x0=0x7000 {pre} mem_w=0x7000"]
    for i, reg in enumerate(source_regs):
        alias = "x" + reg[1:]
        lines.append(f"[App] 0x40200{4+i*4:x}!0x200{4+i*4:x} mov {reg}, #0; -> {alias}=0x0")
    lines += EXIT.splitlines()
    if load:
        lines.append(f"[App] 0x401004!0x1004 {load}, [x0]; x0=0x7000 mem_r=0x7000 -> {post}")
    else:
        lines.append("[App] 0x401004!0x1004 nop; x0=0x7000")
    for i, reg in enumerate(load_regs):
        alias = "x" + reg[1:]
        lines.append(f"[App] 0x40100{8+i*4:x}!0x100{8+i*4:x} mov {reg}, #0; -> {alias}=0x0")
    lines += ["[App] 0x401020!0x1020 ret; x0=0x7000", "[App] 0x400004!0x4 nop; x0=0x7000"]
    return "\n".join(lines)+"\n"
for store, load, size, pre, post, src, dst in [
    ("strb w1","ldrb w3",1,"x1=0x142","x3=0x42",["w1"],["w3"]),
    ("strh w1","ldrh w3",2,"x1=0x142","x3=0x142",["w1"],["w3"]),
    ("str w1","ldr w3",4,"x1=0x142","x3=0x142",["w1"],["w3"]),
    ("stp w1, w2","ldp w3, w4",8,"x1=0x14 x2=0x13","x3=0x14 x4=0x13",["w1","w2"],["w3","w4"]),
    ("stp x1, x2","ldp x3, x4",16,"x1=0x14 x2=0x13","x3=0x14 x4=0x13",["x1","x2"],["x3","x4"]),
    ("stp wzr, wzr","ldp w3, w4",8,"","x3=0x0 x4=0x0",[],["w3","w4"]),
]:
    trace = width_trace(store,pre,load,post,src,dst)
    request = dict(REQUEST,slot_ranges=[dict(address="0x7000",size=size)])
    result = invoke(trace,request)
    assert result["coverage"]["complete"] and not result["uses"] and not result["gaps"], result
    if src:
        bad = invoke(trace.replace(pre,pre.split()[0] if len(src)==2 else ""),request)
        assert not bad["coverage"]["complete"] and bad["gaps"], bad
    if dst:
        escaped = trace.replace(f"mov {dst[0]}, #0; -> x{dst[0][1:]}=0x0",f"ldr x7, [x{dst[0][1:]}]; x{dst[0][1:]}=0x14 mem_r=0x14 -> x7=0x0")
        bad = invoke(escaped,request)
        assert not bad["coverage"]["complete"], bad
# Two W elements totaling eight bytes do not establish an independent X slot.
joined = width_trace("stp w1, w2","x1=0x14 x2=0x13","ldr x3","x3=0x1300000014",["w1","w2"],["x3"])
result = invoke(joined)
assert not result["coverage"]["complete"] and not result["uses"], result
# W/X aliases cannot be killed by a masked or conflicting upper-half observation.
alias = width_trace("strb w1","x1=0x42","ldrb w3","x3=0x42",["w1"],["w3"])
result = invoke(alias.replace("mov w1, #0; -> x1=0x0", "mov w1, #0; -> x1=0x100000000"),dict(REQUEST,slot_ranges=[dict(address="0x7000",size=1)]))
assert not result["coverage"]["complete"], result
# Known partial overwrite merges final bytes, but cannot resurrect the old X slot.
merged = width_trace("str x1","x1=0x1122334455667788",None,"",["x1"],[])
merged = merged.replace(EXIT,"[App] 0x402008!0x2008 strb w2, [x0, #1]; x0=0x7000 x2=0xaa mem_w=0x7001\n[App] 0x40200c!0x200c mov w2, #0; -> x2=0x0\n"+EXIT)
result = invoke(merged)
assert result["coverage"]["complete"] and not result["uses"], result
bad = invoke(merged.replace("x2=0xaa", ""))
assert not bad["coverage"]["complete"], bad
print("real FD output-slot demonstrations passed: narrow/pair/zero/partial-byte negative; unknown-half and narrow escape rejection;" )
print("real FD output-slot demonstrations passed: complete scalar store/load/kill; final pointer positive; unknown usage incomplete; partial/unknown; transient scalar overwrite; store-data/return escape incomplete; owner/selector and strict protocol rejection")
