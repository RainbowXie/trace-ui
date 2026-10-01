"""Small real FD address query: data width/value never grants pointer origins."""
import json
import os
import subprocess
import sys
import tempfile

HELPER = sys.argv[1]
REQUEST = dict(kind="address_provenance", call_seq=1, entry_seq=2,
               function="App+0x2000", target_modules=["App"])

def invoke(instructions, prefix="", entry="x0=0x7000 x1=0x7000 x3=0x0"):
    body = [f"[App] 0x{0x402000 + n*4:x}!0x{0x2000 + n*4:x} {insn}"
            for n, insn in enumerate(instructions)]
    # Actual entry prestate, not a fabricated previous immediate definition.
    body[0] += " " + entry
    trace = "\n".join([
        "[App] 0x400000!0x0 bl #0x401000; " + prefix,
        "[App] 0x401000!0x1000 bl #0x402000;",
        *body,
        f"[App] 0x{0x402000+len(body)*4:x}!0x{0x2000+len(body)*4:x} ret; lr=0x401004",
        "[App] 0x401004!0x1004 ret; lr=0x400004",
        "[App] 0x400004!0x4 nop;", ""])
    with tempfile.TemporaryDirectory(prefix="address-provenance-") as d:
        path = os.path.join(d, "trace.log")
        with open(path, "w") as f:
            f.write(trace)
        with open(path, "rb") as f:
            result = subprocess.run([HELPER, "--function-facts-helper", "--trace-fd", str(f.fileno())],
                input=json.dumps(REQUEST).encode(), capture_output=True, pass_fds=(f.fileno(),))
        assert result.returncode == 0, result.stderr.decode()
        return json.loads(result.stdout)

def complete(p):
    assert p["coverage"]["complete"] and not p["gaps"], p

for mnemonic, regs, width in [
    ("strb", "w2", 1), ("strh", "w2", 2), ("str", "w2", 4),
    ("stp", "w2, w4", 8), ("stp", "x2, x4", 16),
    ("ldrb", "w2", 1), ("ldrh", "w2", 2), ("ldr", "w2", 4),
    ("ldp", "w2, w4", 8), ("ldp", "x2, x4", 16),
    ("strb", "wzr", 1), ("ldrb", "wzr", 1), ("ldp", "xzr, xzr", 16),
]:
    marker = "mem_w" if mnemonic.startswith("st") else "mem_r"
    p = invoke([f"{mnemonic} {regs}, [x0, #8]; {marker}=0x7008"])
    complete(p)  # Missing data is not missing address evidence.
    assert p["coverage"]["access_count"] == 1
    a = p["accesses"][0]
    assert (a["size"], a["address"], a["integer_delta"]) == (width, "0x7008", 8), a
    assert a["origin_anchor"]["kind"] == "abi_register", a
    assert a["origin_anchor"]["register"] == "x0" and a["definition_steps"][-1]["operation"] == "address", a

for definition in [
    "ldrb w0, [x0]; mem_r=0x7000 -> x0=0x7000",
    "ldr x0, [x0]; mem_r=0x7000 -> x0=0x7000",
    "ldp w2, w0, [x0]; mem_r=0x7000 -> x2=0x1 x0=0x7000",
    "ldp x2, x0, [x0]; mem_r=0x7000 -> x2=0x1 x0=0x7000",
    "mov w0, w1; x1=0x7000 -> x0=0x7000",
]:
    # Put entry pre before the arrow; entry is a separate actual nop.
    p = invoke(["nop;", definition, "strb w2, [x0]; x0=0x7000 mem_w=0x7000"])
    assert not p["coverage"]["complete"] and p["accesses"][-1]["origin_anchor"] is None, p

p = invoke(["nop;", "ldrb wzr, [x0]; x0=0x7000 mem_r=0x7000", "strh wzr, [x0]; x0=0x7000 mem_w=0x7000"])
complete(p)
for operand in ["[w0]", "[x0, x1]", "[x0]!", "[x0], #4"]:
    p = invoke([f"ldr w2, {operand}; mem_r=0x7000"])
    assert not p["coverage"]["complete"], p
for entry in ["x0=0x7000 x0=0x7100", "x0=0x7000 w0=0x1", "w0=0x7000"]:
    p = invoke(["strb w2, [x0]; mem_w=0x7000"], entry=entry)
    assert not p["coverage"]["complete"] and any(g["kind"] == "entry_definition" for g in p["gaps"]), p
p = invoke(["strb w2, [x0]; mem_w=0x7000"], prefix="-> x0=0x7100")
assert not p["coverage"]["complete"] and any(g["kind"] == "entry_definition" for g in p["gaps"]), p
# Loaded ordinary data never gains a pointer origin, even with a full X value.
p = invoke(["nop;", "ldr x2, [x0]; x0=0x7000 mem_r=0x7000 -> x2=0x8000",
            "strb wzr, [x2]; x2=0x8000 mem_w=0x8000"])
assert not p["coverage"]["complete"] and p["accesses"][-1]["origin_anchor"] is None, p
p = invoke(["nop;", "mystery x2, x0; x0=0x7000 -> x2=0x7000",
            "strb wzr, [x0]; x0=0x7000 mem_w=0x7000"])
assert not p["coverage"]["complete"] and any(g["kind"] == "unsupported_instruction" for g in p["gaps"]), p
# Existing known replay is allowed when no entry observation exists; zero is known.
p = invoke(["strb wzr, [x0]; x0=0x0 mem_w=0x0"], prefix="-> x0=0x0", entry="")
complete(p)
print("real FD address provenance passed: B/H/W/pair actual range, unknown data, entry consistency, pair second DEF, W/X collision kills, discarded loads and unsupported addresses")
