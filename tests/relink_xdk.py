#!/usr/bin/env python3
"""Local integration: python3 tests/relink_xdk.py --linker ... --wine-prefix ... .

Builds a synthetic fixture, links it with XDK, verifies symbol VAs and bytes.
Only synthetic inputs and outputs enter its temporary directory.
"""
import argparse
import os
from pathlib import Path
import struct
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--linker', type=Path, required=True)
p.add_argument('--wine-prefix', type=Path, required=True)
a = p.parse_args()
env = os.environ | {'WINEPREFIX': str(a.wine_prefix.resolve()), 'WINEDLLOVERRIDES': 'msvcr80,msvcp80=n', 'WINEDEBUG': '-all'}
with tempfile.TemporaryDirectory(prefix='jeff-link-fixture-') as tmp:
    directory = Path(tmp)
    subprocess.run(['cargo', 'test', 'link_contributions_preserve_identity_order_and_padding'],
                   env=env | {'JEFF_RELINK_FIXTURE_DIR': tmp}, check=True)
    def win(path):
        return subprocess.check_output(['winepath', '-w', str(path.resolve())], env=env, text=True).strip()
    output, mapfile = directory/'fixture.exe', directory/'fixture.map'
    subprocess.run(['wine', str(a.linker.absolute()), '/NOLOGO', '/MACHINE:PPCBE', '/SUBSYSTEM:XBOX', '/XEX:NO',
                    '/FIXED', '/BASE:0x82000000', '/ALIGN:4096', '/NODEFAULTLIB',
                    '/ENTRY:?Duplicate@Fixture@@QAAXXZ', '/INCREMENTAL:NO', '/OPT:NOREF', '/OPT:NOICF',
                    '/OUT:'+win(output), '/MAP:'+win(mapfile),
                    *[win(obj) for obj in sorted(directory.glob('*.obj'), reverse=True)]], env=env, check=True)
    data = output.read_bytes()
    header, = struct.unpack_from('<I', data, 60)
    count, = struct.unpack_from('<H', data, header+6)
    opt, = struct.unpack_from('<H', data, header+20)
    sections = {}
    for index in range(count):
        name, size, rva, raw, offset = struct.unpack_from('<8sIIII', data, header+24+opt+40*index)
        sections[name.rstrip(b'\0').decode()] = (0x82000000+rva, data[offset:offset+size])
    text_va, text = sections['.text']
    assert text_va == 0x82010000, hex(text_va)
    expected = [0x48000018, 0x4800000c, 0x48000014, 0x4182000c,
                0x4bfffff0, 0x60000000, 0x4e800020, 0x4e800020,
                0x3c608202, 0x38638004, 0x60000000, 0x4e800020]
    assert text == b''.join(struct.pack('>I', w) for w in expected), text.hex()
    assert sections['.pdata'][1] == struct.pack('>IIII', text_va, 0x80000004, text_va+16, 0x80000004)
    assert b'\x01\x02\x03\x04\0\0\0\0\x05\x06\x07\x08' in sections['.rdata'][1]
    maptext = mapfile.read_text()
    for name, address in [('?Duplicate@Fixture@@QAAXXZ', text_va),
                          ('?Duplicate@Fixture@@QAAXXZ_82001010', text_va+16),
                          ('$LNfixture', text_va+24), ('__restgprlr_20', text_va+28)]:
        row = next(line for line in maptext.splitlines() if name in line.split())
        assert f'{address:08x}' in row.lower(), row
    print('XDK fixture: linked; all symbol VAs, branches, address addends, pdata and padding verified')
