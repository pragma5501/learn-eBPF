from bcc import BPF
from time import sleep


program = """
BPF_HASH(counter_table);

int catch_syscall(struct bpf_raw_tracepoint_args *ctx) {
    u64 opcode = ctx->args[1];
    u64 counter = 0;
    u64 *p;
    
    p = counter_table.lookup(&opcode);
    if ( p != 0 ) {
        counter = *p;
    }
    counter++;
    counter_table.update(&opcode, &counter);
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="catch_syscall")


while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"syscall {k.value}: {v.value}\n"
        
    print(s)

