# <p align="center"><a href="https://www.youtube.com/watch?v=0OzXZGA1k3s" target="_blank"><img width="256" height="256" alt="jeff" src="https://github.com/user-attachments/assets/fd2778fb-8d5f-4113-a9af-583ee8028748"/></a></p>

Forked from and inspired by [encounter's GC/Wii decomp toolkit](https://github.com/encounter/decomp-toolkit), jeff is 
a decomp-toolkit meant for disassembling Xbox 360 executables (xex files). It aims to assist potential Xbox 360 decompilation projects with
the same benefits that encounter's toolkit provides, including function boundary analysis, relocation restorations, splits, and integration
with other decompilation tools like [objdiff](https://github.com/encounter/objdiff) and
[decomp.me](https://decomp.me).

Much like the original GC/Wii decomp toolkit, jeff aims to automate as much of the decompilation setup process as possible,
allowing developers to spend less time configuring a project and more time focusing on what matters most in a decomp: matching code.

I had made jeff with the goal of starting up a [decomp for Dance Central 3](https://github.com/rjkiv/dc3-decomp),
but realized the potential jeff has to work with several other Xbox 360 games, and thus, tried to add support for that to the best of my ability.

**DISCLAIMER**: Although I genuinely tried my best to get jeff working with the pool of xex files I had to test with,
**I make absolutely zero guarantees that this will work out of the box with every last Xbox 360 game! Expect bugs!**

If you spot a bug or crash, please submit an issue, and I will try my best to help you through it.

For use in a new decompilation project, see [jeff-template](https://github.com/rjkiv/jeff-template), which provides a
project structure and build system that uses jeff under the hood.

## Features
- Can extract an exe from an xex using: `xex extract <xex location>`.
You supply the xex, and the underlying exe will be extracted to the same directory - it'll even have its original name the developers gave it!
- Can print out information about an xex using: `xex info <xex location>`.
This aims to replicate the behavior of the original xextool by xorloser.
- Can write down inferred splits, symbols, and COFFs from an xex using: `xex split <config.yml>`.
This is NOT meant to be run on its own, but rather part of a build system, such as the one in the jeff-template above.

## Known Issues/Hacks
- Parsing/applying .pdb files currently has limited support.
- Upstream's default COFFs target objdiff, not a native relink. This TU2 fork adds
  a separate opt-in output described below. A byte-identical extracted PE also
  needs the project's container-normalization step; native link.exe headers and
  metadata layout differ from the XEX-extracted container.
- Because this was forked from encounter's GC/Wii toolkit, there is naturally still a lot of loose GC/Wii tailored code in this codebase that needs removing/refactoring.

## Opt-in relink objects (TU2 fork)

```sh
jeff xex split config.yml build/TU2 --relink
```

The usual `obj/` files and `config.json` keep their original output. The flag
adds `relink/obj/` and `relink/config.json`, reusing the image-wide symbol
identities from `01752b4`. Each code/data range has an address suffix such as
`.text$825199A8`; explicit zero-gap contributions preserve alignment bytes.
Link objects retain PE section flags, relocation addends, the initialized/BSS
boundary, and original XEX import tokens. Default objects retain the unstripped
imports used by objdiff.

For references that exist only in compiled source, `coff_exports: [lbl_8208C474]`
in the split configuration requests extra external identities after split layout
is fixed. Existing names keep the identity pass's spelling. A missing
`lbl_XXXXXXXX` may alias an existing configured symbol at exactly that address;
it never replaces the canonical name or invents an arbitrary address. An empty
list preserves default object hashes. The consumer scans source identifiers into
this list on its scratch configuration and audits the affected default objects:
only added external symbols and the necessary symbol-index remapping are allowed,
with unchanged section bytes/layout and relocation identities. Missing configured
identities are warned about and remain unresolved for the consumer to exclude.

The PPCBE writer uses instruction-start REFHI/REFLO fixups with PAIR records,
and contribution-relative REL14/REL24 addends. Already-resolved branches inside
one contribution stay resolved. The zero-fill tail uses `.dataz$<address>` and
requires `/MERGE:.dataz=.data`; this sorts it after initialized `.data` input.
Singleton Xbox/PE metadata remains opaque. On TU2, the `.reloc` payload is an
address-ordered contribution after `.XBLD`, and `.XEXID` temporarily clears its
nonpageable flag so link.exe preserves its packed VA. The consumer wrapper
supplies header/metadata padding, then restores the original PE container
layout around the linked bytes. This is extraction/relink support, not XEX
signing or a general replacement for the XDK's image builder.

The consumer's [relink notes](https://github.com/asc3ns10n/RiseOfARecomp/blob/work/relink2/docs/RELINK.md)
describe the XDK invocation, native-versus-normalized results, and opt-in Ninja
rules. Install this build beside the matching binary, never over it:

```sh
cargo build --release
install -m 755 target/release/jeff ~/.local/bin/jeff-roan-tu2-relink
```

Validation:

```sh
cargo test
python3 tests/relink_xdk.py --linker "$XDK_LINKER" --wine-prefix "$WINEPREFIX"
```

`default_split_output_unchanged` fixes the fixture's pre-change COFF hashes; it
was committed and passed before implementation (`a3d2df9`). The XDK test uses
only synthetic input and checks duplicate names, cross-object labels,
interleaved contributions, REL14/REL24, high/low address addends, `.pdata`, and
padding at their linked VAs. The XDK/runtime are supplied locally and are not
part of the repository.

## Want to contribute?
Whether you want to add a new feature, or would like to fix one of the known issues, I would love your contribution!
Feel free to fork this repo and submit a PR containing your change. Every little improvement helps jeff become a better resource for the greater decomping community!

Although this is an Xbox 360 centric repo, feel free to join the [GC/Wii Decompilation Discord](https://discord.gg/hKx3FJJgrV) as well!

## Acknowledgements
- [encounter](https://github.com/encounter) - not only for his work on the original GC/Wii toolkit as well as several other decompilation tools, but for his constant help and guidance throughout jeff's creation process
- [The RB3 Decomp and its contributors](https://github.com/DarkRTA/rb3) - for providing additional guidance and suggestions throughout development
