from bcc import BPF
import ctypes as ct

program = r"""
BPF_PROG_ARRAY(syscall, 300);

RAW_TRACEPOINT_PROBE(sys_enter) 
{
    
}

int hello(struct bpf_raw_tracepoint_args *ctx) {
    
    int opcode = ctx->args[1];
    syscall.call(ctx, opcode);
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

int hello_exec(void* ctx) {
    bpf_trace_printk("Executing a program");
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args* ctx) {
    if (ctx->args[1] == 222) {
        bpf_trace_printk("Creating a timer");
    } else if (ctx->args[1] == 226) {
        bpf_trace_printk("Deleting a timer");
    } else {
        bpf_trace_printk("Some other timer operation");
    }
    return 0;

}

int ignore_opcode(void* ctx) {
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn   = b.load_func("hello_exec",    BPF.RAW_TRACEPOINT)
timer_fn  = b.load_func("hello_timer",   BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")

prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)

opcodes_timer = [222, 223, 224, 225, 226]
for opcode in opcodes_timer:
    prog_array[ct.c_int(opcode)] = ct.c_int(timer_fn.fd)
    
opcodes_ignore = [0, 1, 10, 13, 14, 21, 22, 25, 29, 56, 57, 63, 64, 66, 72, 73, 79, 98, 101, 115, 131, 134, 135,139, 172, 233, 280, 291]
for opcode in opcodes_ignore:
    prog_array[ct.c_int(opcode)] = ct.c_int(ignore_fn.fd)
    
b.trace_print()