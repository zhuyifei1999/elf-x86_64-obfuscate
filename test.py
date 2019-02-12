import random
import re
import struct
import sys

import capstone
from capstone import x86_const
import keystone
import lief

binary = lief.parse(sys.argv[1])

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


# HACK: so we can set attrs
class AttrWrapper:
    def __init__(self, insn):
        self._insn = insn

    def __getattr__(self, name):
        return getattr(self._insn, name)


def disasm(*args, **kwargs):
    for insn in cs.disasm(*args, **kwargs):
        insn = AttrWrapper(insn)
        insn.operands = list(map(AttrWrapper, insn.operands))
        for operand in insn.operands:
            operand.value = AttrWrapper(operand.value)
            operand.value.mem = AttrWrapper(operand.value.mem)
        yield insn


all_insn = {}

sections = list(binary.sections)
sections_segments = []
orig_section_contents = {}

for section in sections:
    # FIXME: section is mutable but hashable, mutation changes hash
    orig_section_contents[id(section)] = section.content

    for segment in section.segments:
        sections_segments.append((section, segment))

    if lief.ELF.SECTION_FLAGS.EXECINSTR not in section.flags_list:
        continue

    insns = disasm(bytes(section.content), section.virtual_address)
    for insn in insns:
        insn.section = section
        all_insn[insn.address] = insn


def RawInsn(data, addr):
    backing = object()
    insn = AttrWrapper(backing)
    insn.address = addr
    insn.mnemonic = '.bytes'
    insn.op_str = ', '.join(map(hex, data))
    insn.bytes = bytes(data)
    insn.size = len(data)
    insn.groups = ()
    insn.operands = ()
    return insn


def print_insn(insn):
    try:
        print(f'%s:' % insn.label)
    except AttributeError:
        pass

    print(f'0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}')
    print('\t' + ' '.join(map(hex, insn.bytes)))

    if insn.operands:
        print(f'\tNumber of operands: {len(insn.operands)}')
        for op_i, operand in enumerate(insn.operands):
            if operand.type == x86_const.X86_OP_REG:
                print(f'\t\top[{op_i}].type: '
                      f'REG = {insn.reg_name(operand.value.reg)}')
            if operand.type == x86_const.X86_OP_IMM:
                print(f'\t\top[{op_i}].type: '
                      f'IMM = 0x{operand.value.imm:x}')
            if operand.type == x86_const.X86_OP_MEM:
                print(f'\t\top[{op_i}].type: MEM')
                if operand.value.mem.segment != 0:
                    print(f'\t\t\top[{op_i}].mem.segment: '
                          f'0x{operand.value.mem.segment:x}')
                if operand.value.mem.base != 0:
                    print(f'\t\t\top[{op_i}].mem.base: '
                          f'REG = {insn.reg_name(operand.value.mem.base)}')
                if operand.value.mem.index != 0:
                    print(f'\t\t\top[{op_i}].mem.index: '
                          f'REG = {insn.reg_name(operand.value.mem.index)}')
                if operand.value.mem.scale != 1:
                    print(f'\t\t\top[{op_i}].mem.scale: '
                          f'0x{operand.value.mem.scale:x}')
                if operand.value.mem.disp != 0:
                    print(f'\t\t\top[{op_i}].mem.disp: '
                          f'0x{operand.value.mem.disp:x}')

            try:
                print(f'\t\top[{op_i}].label: {operand.label}')
            except AttributeError:
                pass


all_labels = {}
label_ord = 0


def mk_label(addr):
    try:
        return next(filter(lambda kv: resolve_label(kv[0]) == addr,
                           all_labels.items()))[0]
    except StopIteration:
        pass

    global label_ord
    label = f'label_{label_ord}'

    try:
        insn = all_insn[addr]
    except KeyError:
        all_labels[label] = addr
    else:
        insn.label = label
        all_labels[label] = insn

    label_ord += 1
    return label


def resolve_label(label):
    addr = all_labels[label]
    if isinstance(addr, int):
        return addr

    return addr.address


def insn_is_jmping(insn):
    return {x86_const.X86_GRP_JUMP, x86_const.X86_GRP_CALL} & set(insn.groups)


def resolve_operand_addr(insn, operand):
    if (
        insn_is_jmping(insn) and
        operand.type == x86_const.X86_OP_IMM
    ):
        return operand.value.imm
    elif operand.value.mem.base in {
        x86_const.X86_REG_RIP,
        x86_const.X86_REG_EIP,
        x86_const.X86_REG_IP
    }:
        return insn.address + insn.size + operand.value.mem.disp
    else:
        return None


def rev_resolve_operand_addr(insn, operand, addr):
    if (
        insn_is_jmping(insn) and
        operand.type == x86_const.X86_OP_IMM
    ):
        operand.value.imm = addr
    elif operand.value.mem.base in {
        x86_const.X86_REG_RIP,
        x86_const.X86_REG_EIP,
        x86_const.X86_REG_IP
    }:
        operand.value.mem.disp = addr - (insn.address + insn.size)
    else:
        raise AssertionError


for insn in all_insn.values():
    for operand in insn.operands:
        addr = resolve_operand_addr(insn, operand)
        if addr:
            operand.label = mk_label(addr)


addr_fixups = {}

for reloc in binary.relocations:
    addr_fixups[reloc.address] = mk_label(reloc.address)
    if reloc.type == lief.ELF.RELOCATION_X86_64.RELATIVE:
        addr_fixups[reloc.addend] = mk_label(reloc.addend)


dyn_addrs = {
    # https://refspecs.linuxfoundation.org/LSB_2.1.0/LSB-Core-generic/LSB-Core-generic/dynsectent.html
    lief.ELF.DYNAMIC_TAGS.FINI,
    lief.ELF.DYNAMIC_TAGS.HASH,
    lief.ELF.DYNAMIC_TAGS.HIPROC,
    lief.ELF.DYNAMIC_TAGS.INIT,
    lief.ELF.DYNAMIC_TAGS.JMPREL,
    lief.ELF.DYNAMIC_TAGS.LOPROC,
    lief.ELF.DYNAMIC_TAGS.REL,
    lief.ELF.DYNAMIC_TAGS.RELA,
    lief.ELF.DYNAMIC_TAGS.STRTAB,
    lief.ELF.DYNAMIC_TAGS.SYMTAB,
    lief.ELF.DYNAMIC_TAGS.FINI_ARRAY,
    lief.ELF.DYNAMIC_TAGS.INIT_ARRAY,
    # lief.ELF.DYNAMIC_TAGS.SYMINFO, not defined
    lief.ELF.DYNAMIC_TAGS.VERDEF,
    lief.ELF.DYNAMIC_TAGS.VERNEED,
    lief.ELF.DYNAMIC_TAGS.VERSYM,
    # https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html
    lief.ELF.DYNAMIC_TAGS.PLTGOT,
    # lief.ELF.DYNAMIC_TAGS.MOVETAB, not defined
}

for dynamic in binary.dynamic_entries:
    if dynamic.tag in dyn_addrs:
        addr_fixups[dynamic.value] = mk_label(dynamic.value)


for symbol in binary.symbols:
    if symbol.value:
        addr_fixups[symbol.value] = mk_label(symbol.value)


try:
    pltgot_sect = binary[lief.ELF.DYNAMIC_TAGS.PLTGOT]
except lief.not_found:
    pltgot_sect = None
else:
    pltgot_sect = binary.section_from_virtual_address(pltgot_sect.value)
    pltgot_content = bytearray(pltgot_sect.content)
    assert len(pltgot_content) % 8 == 0
    for i in range(0, len(pltgot_content), 8):
        addr, = struct.unpack('<Q', pltgot_content[i:i+8])
        if addr:
            addr_fixups[addr] = mk_label(addr)


if binary.header.entrypoint:
    addr_fixups[binary.header.entrypoint] = mk_label(binary.header.entrypoint)


def alignto(addr, alignment):
    return (addr - 1 | (alignment - 1)) + 1


new_insn = list(all_insn.values())
DEBUG_watch_insn = {
    # all_insn[0x608]
    # all_insn[0x566]
}


def replace_insn(old, new):
    old, new = map(list, (old, new))
    for insn in old:
        # please, don't have a label here
        try:
            next(filter(lambda kv: kv[1] == insn, all_labels.items()))
        except StopIteration:
            continue
        else:
            return

    # don't span multiple sections
    affected_section = {insn.section for insn in old}
    if len(affected_section) > 1:
        return
    affected_section = next(iter(affected_section))
    for insn in new:
        insn.section = affected_section

    initoff = off = old[0].address
    for insn in new:
        insn.address = off
        off += insn.size

    # TODO: old could be a list, check sublist, not just first item
    index = new_insn.index(old[0])
    new_insn[index:index+len(old)] = new

    size_fixups = []
    oldlen = sum(insn.size for insn in old)
    newlen = sum(insn.size for insn in new)
    if oldlen != newlen:
        size_fixups.append([
            initoff,
            sum(insn.size for insn in old),
            sum(insn.size for insn in new),
            list(new)
        ])
    while size_fixups:
        startpos, oldlen, newlen, nomove = size_fixups.pop(0)
        diff = newlen - oldlen

        sect_changes = {}
        affected_section = binary.section_from_virtual_address(startpos)
        sect_changes[(affected_section.name, 'size')] = affected_section.size \
            + diff
        for i in range(sections.index(affected_section)+1, len(sections)):
            prev_s, next_s = sections[i-1:i+1]
            new_offset = alignto(
                sect_changes.get((prev_s.name, 'offset'), prev_s.offset) +
                sect_changes.get((prev_s.name, 'size'), prev_s.size),
                next_s.alignment
            )
            if new_offset != next_s.offset:
                sect_changes[(next_s.name, 'offset')] = new_offset
                if next_s.virtual_address:
                    def load_segm_from_sect(sect):
                        segm = {
                            seg for sec, seg in sections_segments
                            if sec == sect
                            and seg.type == lief.ELF.SEGMENT_TYPES.LOAD
                        }
                        assert len(segm) <= 1
                        return next(iter(segm)) if segm else None

                    new_virt = new_offset + (
                        sect_changes.get(
                            (prev_s.name, 'virtual_address'),
                            prev_s.virtual_address) -
                        sect_changes.get(
                            (prev_s.name, 'offset'), prev_s.offset)
                    )
                    next_seg = load_segm_from_sect(next_s)
                    if load_segm_from_sect(prev_s) != next_seg:
                        new_virt -= new_offset
                        new_virt = alignto(new_virt, next_seg.alignment)
                        new_virt += new_offset + next_seg.alignment

                    sect_changes[(next_s.name, 'virtual_address')] = (
                        new_virt)

        def calc_diff(addr):
            try:
                section = binary.section_from_virtual_address(addr)
            except lief.not_found:
                # end symbol
                section = binary.section_from_virtual_address(addr - 1)
            if section is affected_section:
                if addr >= startpos + oldlen:
                    return diff
                return 0
            else:
                try:
                    return sect_changes[(section.name, 'virtual_address')] \
                        - section.virtual_address
                except KeyError:
                    return 0

        for item in size_fixups:
            item[0] += calc_diff(item[0])

        # fix non-instruction labels
        for label, addr in list(all_labels.items()):
            # no instructions
            if not isinstance(addr, int):
                continue

            all_labels[label] += calc_diff(addr)

        for insn in new_insn:
            if insn in nomove:
                continue

            if insn in DEBUG_watch_insn:
                print(' '.join(map(hex, (startpos, oldlen, newlen))))
                print(f'{insn.address:x} {calc_diff(insn.address):x}')
                print('NO:', ', '.join(hex(i.address) for i in nomove))

            insn.address += calc_diff(insn.address)

        for (section, attr), val in sect_changes.items():
            setattr(binary.get_section(section), attr, val)

        for insn in new_insn:
            labeled = False
            changed = []

            for operand in insn.operands:
                try:
                    label = operand.label
                except AttributeError:
                    continue
                else:
                    labeled = True
                addr = resolve_label(label)
                if operand.type == x86_const.X86_OP_IMM:
                    oldv = operand.value.imm
                    rev_resolve_operand_addr(insn, operand, addr)
                    newv = operand.value.imm
                    if oldv != newv:
                        changed.append((oldv, newv))
                elif operand.type == x86_const.X86_OP_MEM:
                    oldv = operand.value.mem.disp
                    rev_resolve_operand_addr(insn, operand, addr)
                    newv = operand.value.mem.disp
                    if oldv != newv:
                        changed.append((oldv, newv))
                else:
                    raise AssertionError

            if not changed and (not insn_is_jmping(insn) or not labeled):
                continue

            old_op_str = insn.op_str
            for oldv, newv in changed:
                new_op_str = re.sub(
                    r'\b' + re.escape(f'0x{oldv:x}') + r'\b',
                    f'0x{newv:x}',
                    old_op_str)

                if old_op_str == new_op_str:
                    assert oldv < 0

                    def sign(num):
                        return '+' if num >= 0 else '-'

                    new_op_str = re.sub(
                        sign(oldv) + r'\s*' +
                        re.escape(f'0x{abs(oldv):x}') + r'\b',
                        f'{sign(newv)} 0x{abs(newv):x}',
                        old_op_str)

                    assert old_op_str != new_op_str
                insn.op_str = new_op_str

            newbytes = bytes(ks.asm(
                f'{insn.mnemonic}\t{insn.op_str}', insn.address)[0])
            # assert insn.bytes != newbytes
            insn.bytes = newbytes

            newsize = len(insn.bytes)
            if insn.size != newsize:
                print(f'Resize: 0x{insn.address:x}:\t'
                      f'{insn.mnemonic}\t{old_op_str} => '
                      f'{insn.mnemonic}\t{insn.op_str}; '
                      f'size: {insn.size} => {newsize}')

                size_fixups.append([
                    insn.address,
                    insn.size,
                    newsize,
                    set()
                ])
                insn.size = newsize


# === BEGIN ACTUAL OBFUSCATION LOGIC ===
# XOR-ing movs from imm
# FIXME: XOR affect flags but mov doesn't
# TODO: analyze if flags are needed
for insn in new_insn[:]:
    if insn.mnemonic != 'mov' or len(insn.operands) != 2:
        continue
    dest, src = insn.operands
    if src.type != x86_const.X86_OP_IMM:
        continue

    vals = []
    val = src.value.imm

    # TODO: Figure out how to convert to unsigned
    if val < 0:
        continue
    for n in range(random.randint(2, 10)):
        rand = random.randint(0, 1 << (8 * src.size) - 1)
        vals.append(rand)
        val ^= rand
    vals.append(val)

    if dest.type == x86_const.X86_OP_REG:
        if dest.value.reg not in {
            x86_const.X86_REG_RAX,
            x86_const.X86_REG_EAX,
            x86_const.X86_REG_AX,
            x86_const.X86_REG_AL
        }:
            continue
        dest = insn.reg_name(dest.value.reg)
    else:
        # TODO: make sure it's not IP
        dest = re.match(r'^(.+?),', insn.mnemonic)
        if not dest:
            continue
        dest = dest.group(1)

    asms = ';'.join(f"{'mov' if not i else 'xor'} {dest},0x{val:x}"
                    for i, val in enumerate(vals))

    # print(asms)

    replace_insn(
        [insn],
        disasm(bytes(ks.asm(asms, insn.address)[0]), insn.address)
    )

# Trash nops
for insn in new_insn[:]:
    if insn.mnemonic == 'nop':
        continue

    nop = random.choice([
        b'\x90',
        b'\x66\x90',
        b'\x0f\x1f\x00',
        b'\x0f\x1f\x40\x00',
        b'\x0f\x1f\x44\x00\x00',
        b'\x66\x0f\x1f\x44\x00\x00',
        b'\x0f\x1f\x80\x00\x00\x00\x00',
        b'\x0f\x1f\x84\x00\x00\x00\x00\x00',
        b'\x66\x0f\x1f\x84\x00\x00\x00\x00\x00',
    ])

    replace_insn(
        [insn],
        [insn, next(disasm(nop, 0))]
    )

# Trash bytes, must be last due to not labeled
for insn in new_insn[:]:
    trash = bytes(random.randint(0, 0xff)
                  for i in range(random.randint(0, 0xf)))
    # trash = bytes(0xf4
    #               for i in range(16))

    jmp = bytes([0xeb, len(trash)])

    replace_insn(
        [insn],
        [
            next(disasm(jmp, insn.address)),
            RawInsn(trash, insn.address+len(jmp)),
            insn
        ]
    )
# === END ACTUAL OBFUSCATION LOGIC ===


for insn in new_insn:
    # IDEBUG
    # continue
    print_insn(insn)

for section in sections:
    if lief.ELF.SECTION_FLAGS.EXECINSTR not in section.flags_list:
        section.content = orig_section_contents[id(section)]
        continue

    insns = list(filter(lambda insn: insn.section == section, new_insn))

    section.content = list(b''.join(insn.bytes for insn in insns))
    # if section.virtual_address = insns[0].address

    print(f'{section.name} {section.virtual_address:x} {insns[0].address:x} '
          f'{section.file_offset:x} {section.offset:x}')


# perform segment fixes
def apply_segment(segment, assert_type, sections):
    sections = list(sections)
    assert segment.type == assert_type


phdr_seg = next(filter(
    lambda seg: seg.type == lief.ELF.SEGMENT_TYPES.PHDR, binary.segments))
phdr_load_seg = next(filter(
    lambda seg: seg.type == lief.ELF.SEGMENT_TYPES.LOAD and
    seg.file_offset <= seg.file_offset,
    binary.segments))

sections_segments.append((binary.sections[0], phdr_load_seg))

for segment in {seg for sec, seg in sections_segments}:
    sections = {sec for sec, seg in sections_segments if seg == segment}

    file_offset = min(sect.file_offset for sect in sections)
    fo_end = max(sect.file_offset + sect.size for sect in sections)
    virtual_address = min(sect.virtual_address for sect in sections)
    va_end = max(sect.virtual_address + sect.size for sect in sections)
    assert fo_end - file_offset == va_end - virtual_address
    size = fo_end - file_offset
    segment.file_offset = file_offset
    segment.physical_address = segment.virtual_address = virtual_address
    segment.physical_size = segment.virtual_size = size


for addr, label in list(addr_fixups.items()):
    addr_fixups[addr] = resolve_label(label)
    print(f'Addr Fixup: {addr:x} => {addr_fixups[addr]:x}')


# binary.write('test_edit')
# binary = lief.parse('test_edit')


for reloc in binary.relocations:
    reloc.address = addr_fixups[reloc.address]
    if reloc.type == lief.ELF.RELOCATION_X86_64.RELATIVE:
        reloc.addend = addr_fixups[reloc.addend]

for dynamic in binary.dynamic_entries:
    if dynamic.tag in dyn_addrs:
        dynamic.value = addr_fixups[dynamic.value]

for symbol in binary.symbols:
    if symbol.value:
        symbol.value = addr_fixups[symbol.value]

if pltgot_sect:
    pltgot_content = bytearray(pltgot_sect.content)
    for i in range(0, len(pltgot_content), 8):
        addr, = struct.unpack('<Q', pltgot_content[i:i+8])
        if addr:
            pltgot_content[i:i+8] = struct.pack('<Q', addr_fixups[addr])

    pltgot_sect.content = list(pltgot_content)


if binary.header.entrypoint:
    binary.header.entrypoint = addr_fixups[binary.header.entrypoint]


binary.write('test_edit')

# with open('debugbin', 'wb') as f:
#     f.write(bytes(binary.get_section('.got.plt').content))
