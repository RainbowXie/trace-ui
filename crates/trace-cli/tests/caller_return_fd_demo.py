"""Small real FD-helper demonstrations; no mock facts or services.
Run: python3 crates/trace-cli/tests/caller_return_fd_demo.py /path/to/trace-cli
"""
import json
import os
import subprocess
import sys
import tempfile

HELPER = sys.argv[1]
PREFIX = """[App] 0x400000!0x0 bl #0x401000; x0=0x6000 -> x0=0x6000
[App] 0x401000!0x1000 bl #0x402000; x0=0x6000 -> x0=0x6000
[App] 0x402000!0x2000 mov x0, x1; x1=0x6000 -> x0=0x6000
[App] 0x402004!0x2004 ret; x0=0x6000
"""
POSITIVE = """[App] 0x401004!0x1004 mov x2, x0; x0=0x6000 -> x2=0x6000
[App] 0x401008!0x1008 add x3, x2, #8; x2=0x6000 -> x3=0x6008
[App] 0x40100c!0x100c ldr x4, [x3]; x3=0x6008 mem_r=0x6008 -> x4=0x7
[App] 0x401010!0x1010 ret; x0=0x6000
[App] 0x400004!0x4 nop; x0=0x6000
"""
REQUEST = dict(kind="caller_return_uses", call_seq=1, entry_seq=2,
               function="App+0x2000", target_modules=["App"])

def invoke(trace, request=REQUEST, success=True):
    with tempfile.TemporaryDirectory(prefix="caller-return-") as directory:
        path = os.path.join(directory, "trace.log")
        with open(path, "w") as output:
            output.write(trace)
        with open(path, "rb") as source:
            result = subprocess.run([HELPER, "--function-facts-helper", "--trace-fd", str(source.fileno())],
                                    input=(request if isinstance(request, str) else json.dumps(request)).encode(),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    pass_fds=(source.fileno(),), check=False)
        if not success:
            assert result.returncode != 0, result.stdout
            assert not result.stdout, result.stdout
            return
        assert result.returncode == 0, result.stderr.decode()
        return json.loads(result.stdout)

positive = invoke(PREFIX + POSITIVE)
assert positive["anchors"] == [dict(register="x0", value="0x6000", definition_seq=2, exit_seq=3, resume_seq=4)], positive
assert positive["coverage"]["complete"], positive
assert len(positive["uses"]) == 1, positive
use = positive["uses"][0]
assert use["use_seq"] == 6 and use["address"] == "0x6008" and use["address_operand"] == "[x3]", use
assert use["chain_complete"] and use["integer_delta"] == 8, use
assert [step["operation"] for step in use["definition_steps"]] == ["mov", "add", "address"], use
# Same numeric value after a W alias redefinition is a new identity, not return propagation.
redefined = invoke(PREFIX + POSITIVE.replace("add x3, x2, #8; x2=0x6000 -> x3=0x6008", "mov w2, #0x6008; x2=0x6000 -> x2=0x6008").replace("ldr x4, [x3]; x3=0x6008", "ldr x4, [x2]; x2=0x6008"))
assert not redefined["uses"], redefined
# Store data and another register's address happen to have equal numbers.
data_only = invoke(PREFIX + """[App] 0x401004!0x1004 str x0, [x5]; x0=0x6000 x5=0x6000 mem_w=0x6000
[App] 0x401008!0x1008 ret; x0=0x6000
[App] 0x400004!0x4 nop; x0=0x6000
""")
assert not data_only["uses"] and not data_only["coverage"]["complete"], data_only
assert any(g["kind"] == "store_data_escape" for g in data_only["gaps"]), data_only
unclosed = invoke(PREFIX + POSITIVE.split("[App] 0x40100c")[0])
assert not unclosed["uses"] and not unclosed["coverage"]["complete"], unclosed
assert any(g["kind"] == "caller_not_closed" for g in unclosed["gaps"]), unclosed
# Existing ownership excludes unresolved outer activations: do not guess a prefix owner.
prefix_rejected = invoke(PREFIX + POSITIVE.split("[App] 0x401010")[0])
assert not prefix_rejected["uses"] and not prefix_rejected["coverage"]["complete"], prefix_rejected
assert any(g["kind"] == "return_anchor" for g in prefix_rejected["gaps"]), prefix_rejected
# Existing API also deliberately excludes trace_root ownership: report gaps, not guesses.
trace_root = PREFIX.split("\n", 1)[1] + POSITIVE
root_request = dict(REQUEST, call_seq=0, entry_seq=1)
root_positive = invoke(trace_root, root_request)
assert not root_positive["uses"] and not root_positive["coverage"]["complete"], root_positive
assert any(g["kind"] == "ownership" for g in root_positive["gaps"]), root_positive
invoke(PREFIX + POSITIVE, dict(REQUEST, unexpected=True), False)
invoke(PREFIX + POSITIVE, dict(REQUEST, target_modules=["App", "App"]), False)
invoke(PREFIX + POSITIVE, json.dumps(REQUEST)[:-1] + ',"kind":"caller_return_uses"}', False)
invoke(PREFIX + POSITIVE, dict(REQUEST, kind="unknown_kind"), False)
print("real FD demonstrations passed: copy/add/address; W redefine; store-data equality; incomplete negative/unresolved outer rejection/trace_root rejection; strict protocol")
