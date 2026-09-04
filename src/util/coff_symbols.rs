//! Image-wide COFF identities, prepared before names are serialized or split.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::obj::{ObjInfo, ObjSymbolFlags, ObjSymbolKind, ObjSymbolScope, SymbolIndex};

/// Keep legacy auto-split boundaries on subsequent reads of qualified names.
/// This is only a layout key; it must never be used to resolve a relocation.
pub fn original_name(name: &str, address: u32) -> &str {
    let suffix = format!("_{address:08X}");
    if let Some(base) = name.strip_suffix(&suffix) {
        return base;
    }
    if let Some((stem, counter)) = name.rsplit_once('_') {
        if counter.parse::<u32>().is_ok() {
            if let Some(base) = stem.strip_suffix(&suffix) {
                return base;
            }
        }
    }
    name
}

/// The lowest address keeps the input spelling. Other addresses get `_XXXXXXXX`.
/// Unlike `$XXXXXXXX`, this survives objdiff's numeric-dollar normalization.
pub fn prepare_coff_symbols(obj: &mut ObjInfo) -> Result<()> {
    let mut names: BTreeMap<String, BTreeMap<u32, Vec<SymbolIndex>>> = BTreeMap::new();
    let mut reserved: BTreeSet<String> = obj.symbols.iter().map(|(_, s)| s.name.clone()).collect();
    for (index, symbol) in obj.symbols.iter() {
        if symbol.section.is_some() && symbol.kind != ObjSymbolKind::Section {
            names
                .entry(symbol.name.clone())
                .or_default()
                .entry(symbol.address)
                .or_default()
                .push(index);
        }
    }
    for (name, addresses) in names {
        if addresses.len() < 2 {
            continue;
        }
        log::warn!(
            "Duplicate COFF name {name}: {}",
            addresses
                .keys()
                .map(|address| format!("0x{address:08X}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for (address, indices) in addresses.into_iter().skip(1) {
            let stem = format!("{name}_{address:08X}");
            let mut unique = stem.clone();
            let mut collision = 0;
            while !reserved.insert(unique.clone()) {
                collision += 1;
                unique = format!("{stem}_{collision}");
            }
            for index in indices {
                let mut symbol = obj.symbols[index].clone();
                symbol.name.clone_from(&unique);
                symbol.demangled_name = None;
                obj.symbols.replace(index, symbol)?;
            }
        }
    }

    // Use relocation indices and split ownership, never a lookup by spelling.
    let mut external = BTreeSet::new();
    for (index, symbol) in obj.symbols.iter() {
        // The compiler can reference any entry, including ones unused by the image.
        if symbol.section.is_some()
            && symbol.kind == ObjSymbolKind::Unknown
            && [
                "__savegprlr_",
                "__restgprlr_",
                "__savefpr_",
                "__restfpr_",
                "__savevmx_",
                "__restvmx_",
            ]
            .iter()
            .any(|prefix| {
                symbol
                    .name
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.parse::<u32>().is_ok())
            })
        {
            external.insert(index);
        }
    }
    for (_, section) in obj.sections.iter() {
        for (address, reloc) in section.relocations.iter() {
            let target = &obj.symbols[reloc.target_symbol];
            let Some(target_section) = target.section else {
                continue;
            };
            let source_split = section.splits.for_address(address);
            let target_split = obj.sections[target_section]
                .splits
                .for_address(target.address);
            if let (Some((_, source)), Some((_, destination))) = (source_split, target_split) {
                if !source.skip && !destination.skip && source.unit != destination.unit {
                    external.insert(reloc.target_symbol);
                }
            }
        }
    }
    for index in external {
        let mut symbol = obj.symbols[index].clone();
        // Existing unique label and CRT spellings already identify an address.
        // Preserve them so compiler-generated references resolve without libcMT.
        if symbol.flags.is_local() {
            symbol.flags.set_scope(ObjSymbolScope::Global);
        }
        symbol.flags.0 |= ObjSymbolFlags::CoffExternal;
        obj.symbols.replace(index, symbol)?;
    }
    Ok(())
}

/// COFF externals with null type read as data, even in .text. Give enclosing
/// functions their standard auxiliary size record so objdiff does not truncate
/// them at a promoted label. The object writer has no function-aux API yet.
/// Only the symbol table and relocation symbol indices change; sections do not.
pub fn add_function_sizes(data: Vec<u8>, obj: &ObjInfo) -> Result<Vec<u8>> {
    use anyhow::ensure;
    use object::{Object, ObjectSymbol};
    const SYMBOL_SIZE: usize = size_of::<object::pe::ImageSymbol>();
    const FILE_HEADER_SIZE: usize = size_of::<object::pe::ImageFileHeader>();
    const SECTION_HEADER_SIZE: usize = size_of::<object::pe::ImageSectionHeader>();
    const RELOCATION_SIZE: usize = size_of::<object::pe::ImageRelocation>();
    let coff = object::File::parse(data.as_slice())?;
    let mut sizes = BTreeMap::new();
    for (_, function) in obj
        .symbols
        .iter()
        .filter(|(_, s)| s.kind == ObjSymbolKind::Function)
    {
        let Some(section) = function.section else {
            continue;
        };
        if function.size == 0 {
            continue;
        }
        let end = function.address + function.size;
        if obj
            .symbols
            .for_section_range(section, function.address..end)
            .any(|(_, s)| {
                s.kind != ObjSymbolKind::Function
                    && s.flags.0.contains(ObjSymbolFlags::CoffExternal)
            })
        {
            sizes.insert(function.name.as_str(), function.size);
        }
    }
    let additions: BTreeMap<_, _> = coff
        .symbols()
        .filter_map(|s| sizes.get(s.name().ok()?).map(|&size| (s.index().0, size)))
        .collect();
    if additions.is_empty() {
        return Ok(data);
    }
    let read32 = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    let table = read32(8); // PointerToSymbolTable
    let count = read32(12); // NumberOfSymbols (including auxiliary records)
    let mut remap = vec![0u32; count];
    let mut symbols = Vec::new();
    let mut index = 0;
    while index < count {
        let offset = table + index * SYMBOL_SIZE;
        let aux = data[offset + 17] as usize; // NumberOfAuxSymbols
        remap[index] = (symbols.len() / SYMBOL_SIZE) as u32;
        let mut symbol = data[offset..offset + SYMBOL_SIZE].to_vec();
        if let Some(size) = additions.get(&index) {
            ensure!(
                aux == 0,
                "Unexpected existing COFF function auxiliary record"
            );
            // A size record is defined for an external function.
            symbol[16] = object::pe::IMAGE_SYM_CLASS_EXTERNAL;
            symbol[17] = 1;
            symbols.extend(symbol);
            let mut record = [0u8; SYMBOL_SIZE];
            record[4..8].copy_from_slice(&size.to_le_bytes());
            symbols.extend(record);
        } else {
            symbols.extend(symbol);
            symbols
                .extend_from_slice(&data[offset + SYMBOL_SIZE..offset + SYMBOL_SIZE * (aux + 1)]);
        }
        index += aux + 1;
    }
    let mut result = data[..table].to_vec();
    let section_count = u16::from_le_bytes(data[2..4].try_into().unwrap()) as usize;
    let optional_size = u16::from_le_bytes(data[16..18].try_into().unwrap()) as usize;
    for section in 0..section_count {
        let header = FILE_HEADER_SIZE + optional_size + section * SECTION_HEADER_SIZE;
        let relocations = read32(header + 24); // PointerToRelocations
        let mut count =
            u16::from_le_bytes(data[header + 32..header + 34].try_into().unwrap()) as usize;
        let first = if count == 0xFFFF
            && read32(header + 36) & object::pe::IMAGE_SCN_LNK_NRELOC_OVFL as usize != 0
        {
            count = read32(relocations);
            1 // COFF relocation-overflow sentinel, not a symbol reference
        } else {
            0
        };
        for index in first..count {
            let offset = relocations + index * RELOCATION_SIZE + 4; // SymbolTableIndex
            let old = read32(offset);
            ensure!(
                old < remap.len(),
                "Invalid COFF relocation symbol index {old}"
            );
            result[offset..offset + 4].copy_from_slice(&remap[old].to_le_bytes());
        }
    }
    result[12..16].copy_from_slice(&((symbols.len() / SYMBOL_SIZE) as u32).to_le_bytes());
    result.extend(symbols);
    result.extend_from_slice(&data[table + count * SYMBOL_SIZE..]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obj::{
        ObjKind, ObjReloc, ObjRelocKind, ObjRelocations, ObjSection, ObjSectionKind, ObjSplit,
        ObjSymbol, ObjUnit,
    };
    use crate::util::{
        config::{parse_symbol_line, write_symbols},
        split::split_obj,
        xex::write_coff,
    };
    use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

    const NAME: &str = "?Duplicate@Fixture@@QAAXXZ";

    fn fixture() -> ObjInfo {
        let mut text = ObjSection {
            name: ".text".into(),
            address: 0x82001000,
            size: 32,
            data: [0x60000000u32.to_be_bytes(); 8].concat(),
            align: 4,
            ..Default::default()
        };
        for (start, end, unit) in [(0x82001000, 0x82001010, "a"), (0x82001010, 0x82001020, "b")] {
            text.splits.push(
                start,
                ObjSplit {
                    unit: unit.into(),
                    end,
                    ..Default::default()
                },
            );
        }
        let mut pdata = ObjSection {
            name: ".pdata".into(),
            address: 0x82002000,
            kind: ObjSectionKind::ReadOnlyData,
            size: 16,
            data: [0x82001000u32, 0x80000004, 0x82001010, 0x80000004]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect(),
            align: 4,
            ..Default::default()
        };
        pdata.splits.push(
            0x82002000,
            ObjSplit {
                unit: "pdata".into(),
                end: 0x82002010,
                ..Default::default()
            },
        );
        let mut image = ObjInfo::new(
            ObjKind::Executable,
            "fixture".into(),
            vec![],
            vec![text, pdata],
        );
        image.link_order = ["a", "b", "pdata"]
            .map(|name| ObjUnit {
                name: name.into(),
                autogenerated: false,
                order: None,
            })
            .to_vec();
        // Insert in reverse address order: neither insertion nor relocation order
        // may select the canonical duplicate.
        let second = image
            .symbols
            .add_direct(ObjSymbol {
                name: NAME.into(),
                address: 0x82001010,
                section: Some(0),
                kind: ObjSymbolKind::Function,
                size: 16,
                size_known: true,
                ..Default::default()
            })
            .unwrap();
        let first = image
            .symbols
            .add_direct(ObjSymbol {
                name: NAME.into(),
                address: 0x82001000,
                section: Some(0),
                kind: ObjSymbolKind::Function,
                size: 16,
                size_known: true,
                ..Default::default()
            })
            .unwrap();
        let label = image
            .symbols
            .add_direct(ObjSymbol {
                name: "$LNfixture".into(),
                address: 0x82001018,
                section: Some(0),
                ..Default::default()
            })
            .unwrap();
        let crt = image
            .symbols
            .add_direct(ObjSymbol {
                name: "__restgprlr_20".into(),
                address: 0x8200101C,
                section: Some(0),
                ..Default::default()
            })
            .unwrap();
        let reloc = |target_symbol, kind| ObjReloc {
            target_symbol,
            kind,
            addend: 0,
            module: None,
        };
        image.sections[0].relocations = ObjRelocations::new(vec![
            (0x82001000, reloc(label, ObjRelocKind::PpcRel24)),
            (0x82001004, reloc(second, ObjRelocKind::PpcRel24)),
            (0x82001008, reloc(crt, ObjRelocKind::PpcRel24)),
            (0x82001010, reloc(first, ObjRelocKind::PpcRel24)),
        ])
        .unwrap();
        image.sections[1].relocations = ObjRelocations::new(vec![
            (0x82002000, reloc(first, ObjRelocKind::Absolute)),
            (0x82002008, reloc(second, ObjRelocKind::Absolute)),
        ])
        .unwrap();
        image
    }

    // Golden hashes captured from 01752b4 before any relink implementation.
    // Exercise the default splitter and writer used when link mode is absent.
    #[test]
    fn default_split_output_unchanged() -> Result<()> {
        use sha1::{Digest, Sha1};
        let mut image = fixture();
        prepare_coff_symbols(&mut image)?;
        let hashes = split_obj(&image, None)?
            .iter()
            .map(|obj| {
                Ok((
                    obj.name.clone(),
                    hex::encode(Sha1::digest(write_coff(obj)?)),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(
            hashes,
            vec![
                (
                    "a".into(),
                    "b2d702b6fa0238551c391f5797d660da6f4371d8".into()
                ),
                (
                    "b".into(),
                    "fcf56fc9a7d131195bb202421f97d28a776318b4".into()
                ),
                (
                    "pdata".into(),
                    "b88acc6f930f88d3ceb17e8a3fa69b13ec78ca6f".into()
                ),
            ]
        );
        Ok(())
    }

    #[test]
    fn duplicate_functions_cross_object_label_and_pdata() -> Result<()> {
        let mut image = fixture();
        prepare_coff_symbols(&mut image)?;
        let objects = split_obj(&image, None)?;
        let bytes: Vec<_> = objects.iter().map(write_coff).collect::<Result<_>>()?;
        let mut definitions = BTreeMap::new();
        let mut targets = BTreeMap::new();
        for (obj, data) in objects.iter().zip(&bytes) {
            let coff = object::File::parse(data.as_slice())?;
            if obj.name == "b" {
                let function = coff
                    .symbols()
                    .find(|s| s.name().ok() == Some(&format!("{NAME}_82001010")))
                    .unwrap();
                assert_eq!(
                    function.size(),
                    16,
                    "external labels must not truncate the function"
                );
            }
            for symbol in coff
                .symbols()
                .filter(|s| s.is_definition() && s.is_global())
            {
                let section = &obj.sections[symbol.section_index().unwrap().0 as u32 - 1];
                let address = section.virtual_address.unwrap() as u64 + symbol.address();
                assert!(
                    definitions
                        .insert(symbol.name()?.to_owned(), address)
                        .is_none(),
                    "duplicate external {}",
                    symbol.name()?
                );
            }
            for section in coff.sections() {
                let va = obj.sections[section.index().0 as u32 - 1]
                    .virtual_address
                    .unwrap();
                for (offset, reloc) in section.relocations() {
                    let RelocationTarget::Symbol(index) = reloc.target() else {
                        panic!("not a symbol")
                    };
                    targets.insert(
                        va as u64 + offset,
                        coff.symbol_by_index(index)?.name()?.to_owned(),
                    );
                }
            }
        }
        assert_eq!(definitions[NAME], 0x82001000);
        assert_eq!(definitions[&format!("{NAME}_82001010")], 0x82001010);
        assert_eq!(definitions["$LNfixture"], 0x82001018);
        assert_eq!(definitions["__restgprlr_20"], 0x8200101C);
        for (site, address) in [
            (0x82001000, 0x82001018),
            (0x82001004, 0x82001010),
            (0x82001008, 0x8200101C),
            (0x82001010, 0x82001000),
            (0x82002000, 0x82001000),
            (0x82002008, 0x82001010),
        ] {
            assert_eq!(
                definitions[&targets[&site]], address,
                "relocation at {site:X}"
            );
        }
        // A split and symbols.txt rewrite must reach a fixed point.
        let mut written = Vec::new();
        write_symbols(&mut written, &image)?;
        let mut reloaded = fixture();
        reloaded.symbols = crate::obj::ObjSymbols::new(ObjKind::Executable, vec![]);
        for line in std::str::from_utf8(&written)?.lines() {
            if let Some(symbol) = parse_symbol_line(line, &mut reloaded)? {
                reloaded.symbols.add_direct(symbol)?;
            }
        }
        // Relocations are rebuilt by analysis on a real reload; here check names
        // separately so fixture insertion order doesn't masquerade as an index map.
        for (_, section) in reloaded.sections.iter_mut() {
            section.relocations = Default::default();
        }
        prepare_coff_symbols(&mut reloaded)?;
        let mut rewritten = Vec::new();
        write_symbols(&mut rewritten, &reloaded)?;
        assert_eq!(written, rewritten);
        Ok(())
    }

    #[test]
    fn link_contributions_preserve_identity_order_and_padding() -> Result<()> {
        use crate::util::{relink::link_objects, xex::write_link_coff};
        let mut image = fixture();
        image.sections[0].size = 48;
        image.sections[0].data = [
            0x48000018u32,
            0x4800000C,
            0x48000014,
            0x4182000C,
            0x4BFFFFF0,
            0x60000000,
            0x4E800020,
            0x4E800020,
            0x3C608201,
            0x38639004,
            0x60000000,
            0x4E800020,
        ]
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect();
        image.sections[0].splits.push(
            0x82001020,
            ObjSplit {
                unit: "a".into(),
                end: 0x82001030,
                ..Default::default()
            },
        );
        image.sections[0].relocations.insert(
            0x8200100C,
            ObjReloc {
                target_symbol: 2,
                kind: ObjRelocKind::PpcRel14,
                addend: 0,
                module: None,
            },
        )?;
        for (address, kind) in [
            (0x82001020, ObjRelocKind::PpcAddr16Ha),
            (0x82001024, ObjRelocKind::PpcAddr16Lo),
        ] {
            image.sections[0].relocations.insert(
                address,
                ObjReloc {
                    target_symbol: 1,
                    kind,
                    addend: 0x8004,
                    module: None,
                },
            )?;
        }
        image.sections[1].splits.clear();
        for (start, end, unit) in [(0x82002000, 0x82002008, "a"), (0x82002008, 0x82002010, "b")] {
            image.sections[1].splits.push(
                start,
                ObjSplit {
                    unit: unit.into(),
                    end,
                    ..Default::default()
                },
            );
        }
        let mut rdata = ObjSection {
            name: ".rdata".into(),
            kind: ObjSectionKind::ReadOnlyData,
            address: 0x82003000,
            size: 12,
            data: vec![1, 2, 3, 4, 0, 0, 0, 0, 5, 6, 7, 8],
            align: 4,
            ..Default::default()
        };
        for (start, end, unit) in [(0x82003000, 0x82003004, "a"), (0x82003008, 0x8200300C, "b")] {
            rdata.splits.push(
                start,
                ObjSplit {
                    unit: unit.into(),
                    end,
                    align: Some(4),
                    ..Default::default()
                },
            );
        }
        image.sections.push(rdata);
        prepare_coff_symbols(&mut image)?;
        let defaults = split_obj(&image, None)?;
        let before = defaults
            .iter()
            .map(write_coff)
            .collect::<Result<Vec<_>>>()?;
        let linked = link_objects(&image, &defaults)?;
        assert_eq!(
            before,
            defaults
                .iter()
                .map(write_coff)
                .collect::<Result<Vec<_>>>()?
        );
        let mut contributions = BTreeMap::new();
        for obj in &linked {
            let bytes = write_link_coff(obj)?;
            let coff = object::File::parse(bytes.as_slice())?;
            for section in coff.sections() {
                contributions.insert(section.name()?.to_owned(), section.size());
            }
        }
        assert_eq!(contributions[".text$82001000"], 16);
        assert_eq!(contributions[".text$82001010"], 16);
        assert_eq!(contributions[".text$82001020"], 16);
        assert_eq!(contributions[".pdata$82002000"], 8);
        assert_eq!(contributions[".pdata$82002008"], 8);
        assert_eq!(contributions[".rdata$82003004"], 4);
        // A local XDK harness can link these redistributable synthetic objects.
        if let Ok(path) = std::env::var("JEFF_RELINK_FIXTURE_DIR") {
            std::fs::create_dir_all(&path)?;
            for obj in linked.iter().filter(|o| !o.sections.is_empty()) {
                std::fs::write(
                    std::path::Path::new(&path).join(format!("{}.obj", obj.name)),
                    write_link_coff(obj)?,
                )?;
            }
        }
        Ok(())
    }

    #[test]
    fn link_mode_retains_original_xex_import_tokens() -> Result<()> {
        let mut image = fixture();
        let mut original = image.sections[0].data.clone();
        original[..8]
            .copy_from_slice(&[0x010001A4u32.to_be_bytes(), 0x020001A4u32.to_be_bytes()].concat());
        image.sections[0].original_data = Some(original.clone());
        prepare_coff_symbols(&mut image)?;
        let defaults = split_obj(&image, None)?;
        let linked = crate::util::relink::link_objects(&image, &defaults)?;
        let section = &linked.iter().find(|obj| obj.name == "a").unwrap().sections[0];
        assert_eq!(&section.data[..8], &original[..8]);
        assert!(section.relocations.iter().all(|(offset, _)| offset >= 8));
        assert_ne!(&defaults[0].sections[0].data[..8], &original[..8]);
        Ok(())
    }

    #[test]
    fn generated_names_do_not_collide_with_input_names() -> Result<()> {
        let mut image = fixture();
        image.symbols.add_direct(ObjSymbol {
            name: format!("{NAME}_82001010"),
            address: 0x8200100C,
            section: Some(0),
            ..Default::default()
        })?;
        prepare_coff_symbols(&mut image)?;
        assert_eq!(image.symbols[0].name, format!("{NAME}_82001010_1"));
        Ok(())
    }
}
