# COFF symbol identity

The XEX split command prepares names once for the entire image, after relocation
analysis and before writing either symbols.txt or objects. A definition name at
more than one address produces one WARN listing every address. The lowest address
keeps the original spelling; subsequent addresses receive `_XXXXXXXX` (uppercase,
eight hexadecimal digits). If that spelling is already reserved by any input
symbol, append `_1`, `_2`, etc. Same-address aliases are not different instances.

Address order is deterministic even when both instances have pdata/xidata records;
unwind metadata does not establish which duplicate deserves the undecorated name.
This naming rule does not assert that a recovered C++ name is correct. Projects
should still rename false-positive signatures when they have independent evidence.

Do not use `$XXXXXXXX`: objdiff 3.7.3's `get_normalized_symbol_name` maps a numeric
`$` suffix to `$0000`, losing identity for addresses containing only decimal
digits. Its MSVC anonymous-namespace normalization also rewrites `?A0x` IDs.
An appended underscore-address suffix survives both paths, including names that
already contain MSVC `$` syntax. It is valid COFF text; compiled functions with
the original decorated name need explicit target-to-source objdiff mappings.

Relocations retain their image symbol indices through naming and then use the
splitter's index map. They are never rebound by looking up the first spelling.
Cross-object relocation targets get external definitions, including labels and
locals. Already unique label spellings are retained as their synthetic external
names. All discovered numeric CRT save/restore entries are exported, even if an
entry is only referenced by newly compiled source. They remain offsets in the
extracted bodies, rather than pulling in another CRT library.

COFF represents these external labels with null type (data). Enclosing functions
receive standard function auxiliary size records to preserve their extents for
objdiff. The auxiliary-record insertion remaps relocation symbol-table indices;
it does not change section contents, order, alignment, or contributions.

Input symbols.txt spellings take precedence over automatic signature/CFA names.
Resolved names and any required local-to-global scope promotions are serialized;
transient writer flags are not. A subsequent split must reach the same names.
The auto-gap splitter recognizes address qualifications solely as a layout key
so the legacy duplicate-name split boundaries survive a symbols.txt round-trip.
This key is never used for relocation resolution.

Tests: `cargo test coff_symbols`. The synthetic fixture has two decorated-name
functions, bidirectional calls, a cross-object label, a CRT interior entry, and
one pdata record for each function. It reads emitted COFF to check definition VAs
and every relocation, and checks symbols.txt stability and suffix collisions.
