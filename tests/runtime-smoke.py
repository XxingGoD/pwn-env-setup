import capstone
import keystone
import unicorn
import z3

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
encoding, _ = ks.asm("nop; ret")
assert bytes(encoding) == b"\x90\xc3"
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
assert [i.mnemonic for i in md.disasm(bytes(encoding), 0x1000)] == ["nop", "ret"]
uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
uc.mem_map(0x1000, 0x1000)
uc.mem_write(0x1000, bytes.fromhex("b80100000083c002"))
uc.emu_start(0x1000, 0x1008)
assert uc.reg_read(unicorn.x86_const.UC_X86_REG_EAX) == 3
x = z3.Int("x")
solver = z3.Solver(); solver.add(x + 1 == 2); assert solver.check() == z3.sat and solver.model()[x].as_long() == 1
print("keystone/capstone/unicorn/z3 smoke passed")
