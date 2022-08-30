import gdb
import re

addr_re = "0x[a-fA-F0-9]{16}"
entry_re = "<[a-z_]+>:"
str_re = r'"(?:[^\\]|(?:\\.))*"'

# can use reverse-step to get end address
def get_start_end(fname):
    disassembly = gdb.execute("disas {}".format(fname), True, True).split("\n")
    insns = []
    for insn in disassembly:
        insn_addr = re.findall(addr_re, insn)
        if len(insn_addr) > 0:
            insns.append(insn_addr[0])
    return (insns[0], insns[-1])


def examine_trace(name, main_func_name):
    gdb.execute("file {}".format(name))
    gdb.execute("handle SIGSEGV nostop noprint pass")
    gdb.execute("handle SIGILL nostop noprint pass")

    start, end = get_start_end(main_func_name)
    gdb.execute("b *{}".format(start))
    gdb.execute("b *{}".format(end))
    gdb.execute("""r""")

    # We're at the entrance to main
    rip = int(start, 16)
    while rip != int(end, 16):
        curr_insn = gdb.execute("x/i $rip", True, True)
        print(curr_insn)
        # f.write(curr_insn)
        func = re.search(entry_re, curr_insn)
        if func:
            args = gdb.execute("info args", True, True)
        rip = int(gdb.execute("p/d $rip", True, True).split(" ")[-1])
        gdb.execute("si")
    gdb.execute("q")


if __name__ == "__main__":
    examine_trace("./fuzzer-regcomp", "main")
