//! Opt-in address-ordered link contributions. The objdiff objects are never mutated.
use crate::obj::{ObjInfo, ObjKind, ObjRelocKind, ObjSection, ObjSectionKind};
use anyhow::{Result, ensure};

pub fn link_objects(image: &ObjInfo, defaults: &[ObjInfo]) -> Result<Vec<ObjInfo>> {
    let mut objects: Vec<_> = defaults
        .iter()
        .filter(|obj| !obj.sections.is_empty())
        .cloned()
        .collect();
    // Analysis unstrips XEX imports into executable lis/lwz thunks and PE IAT
    // values for objdiff. Relinking the extracted image must retain its original
    // loader tokens, and must not relocate those tokens as instructions/pointers.
    for object in &mut objects {
        for (_, section) in object.sections.iter_mut() {
            let start = section.virtual_address.unwrap();
            let (_, original) = image.sections.at_address(start)?;
            if let Some(data) = &original.original_data {
                let offset = (start - original.address) as usize;
                let bytes = &data[offset..offset + section.size as usize];
                section.relocations = crate::obj::ObjRelocations::new(
                    section
                        .relocations
                        .iter()
                        .filter(|(offset, _)| {
                            section.data[*offset as usize..*offset as usize + 4]
                                == bytes[*offset as usize..*offset as usize + 4]
                        })
                        .map(|(offset, reloc)| (offset, reloc.clone()))
                        .collect(),
                )?;
                section.data = bytes.to_vec();
            }
        }
    }
    // Preserve the PE's initialized/zero-fill boundary; do not infer storage
    // from byte values (opaque sections can contain long runs of zeros).
    for (_, original) in image.sections.iter() {
        let Some(raw_size) = original.original_raw_size else {
            continue;
        };
        let initialized_end = original.address + raw_size;
        if initialized_end >= original.address + original.size {
            continue;
        }
        for object in &mut objects {
            let mut tails = vec![];
            for (index, section) in object.sections.iter_mut() {
                let start = section.virtual_address.unwrap();
                if section.name != original.name || start + section.size <= initialized_end {
                    continue;
                }
                let cut = initialized_end.saturating_sub(start);
                ensure!(
                    section.relocations.iter().all(|(offset, _)| offset < cut),
                    "Relocation in zero-fill tail"
                );
                if cut == 0 {
                    section.kind = ObjSectionKind::Bss;
                    section.name = format!("{}z", section.name);
                    section.original_flags =
                        section.original_flags.map(|flags| (flags & !0x40) | 0x80);
                    section.data.clear();
                } else {
                    let mut tail = section.clone();
                    tail.size -= cut;
                    tail.virtual_address = Some(start + cut);
                    tail.data.clear();
                    tail.kind = ObjSectionKind::Bss;
                    tail.name = format!("{}z", tail.name);
                    tail.original_flags = tail.original_flags.map(|flags| (flags & !0x40) | 0x80);
                    tail.relocations = Default::default();
                    section.size = cut;
                    section.data.truncate(cut as usize);
                    tails.push((index, cut, tail));
                }
            }
            for (old_index, cut, tail) in tails {
                let new_index = object.sections.next_section_index();
                object.sections.push(tail);
                let symbols = object
                    .symbols
                    .iter()
                    .map(|(_, symbol)| {
                        let mut symbol = symbol.clone();
                        if symbol.section == Some(old_index) && symbol.address >= cut {
                            symbol.section = Some(new_index);
                            symbol.address -= cut;
                        }
                        symbol
                    })
                    .collect();
                object.symbols = crate::obj::ObjSymbols::new(ObjKind::Relocatable, symbols);
            }
        }
    }
    for object in &mut objects {
        for (index, section) in object.sections.iter_mut() {
            // The compiler resolves branches within one contribution itself. Keep
            // these bytes: XDK REL14 fixups overflow for large section offsets.
            let mut local = std::collections::BTreeSet::new();
            for (offset, reloc) in section.relocations.iter() {
                let target = &object.symbols[reloc.target_symbol];
                if matches!(reloc.kind, ObjRelocKind::PpcRel14 | ObjRelocKind::PpcRel24)
                    && target.section == Some(index)
                    && (0..section.size as i64).contains(&(target.address as i64 + reloc.addend))
                {
                    local.insert(offset);
                }
            }
            section.relocations = crate::obj::ObjRelocations::new(
                section
                    .relocations
                    .iter()
                    .filter(|(offset, _)| !local.contains(offset))
                    .map(|(offset, r)| (offset, r.clone()))
                    .collect(),
            )?;

            let address = section
                .virtual_address
                .ok_or_else(|| anyhow::anyhow!("Missing contribution VA"))?;
            // All gaps are explicit, so implicit linker alignment must not insert bytes.
            section.align = 1;
            let opaque = matches!(
                section.name.as_str(),
                ".edata" | ".idata" | ".reloc" | ".XEXID" | ".XBLD" | ".XBMOVIE"
            );
            if opaque {
                section.relocations = Default::default();
            }
            // XDK recognizes these singleton metadata sections by their full
            // names before dollar merging. They have no ordering ambiguity.
            if section.name == ".reloc" && image.sections.iter().any(|(_, s)| s.name == ".XBLD") {
                // XDK forbids /MERGE:.reloc and otherwise puts opaque relocations
                // before its metadata group. Keep them after .XBLD; the PE
                // container layout can expose their original section separately.
                section.name = format!(".XBLD${address:08X}");
            } else if !opaque {
                section.name = format!("{}${address:08X}", section.name);
            }
        }
    }
    // Default splitting omits zero alignment gaps. Preserve their actual bytes here.
    for (_, section) in image.sections.iter() {
        let mut cursor = section.address;
        for (start, split) in section.splits.iter() {
            ensure!(
                !split.skip && !split.common,
                "Link mode requires concrete contributions: {}",
                split.unit
            );
            if cursor < start {
                objects.push(padding(section, cursor, start)?);
            }
            cursor = split.end;
        }
        if cursor < section.address + section.size {
            objects.push(padding(section, cursor, section.address + section.size)?);
        }
    }
    objects.sort_by_key(|obj| {
        obj.sections
            .iter()
            .filter_map(|(_, s)| s.virtual_address)
            .min()
    });
    Ok(objects)
}

fn padding(section: &ObjSection, start: u32, end: u32) -> Result<ObjInfo> {
    let data = if section.kind == ObjSectionKind::Bss {
        vec![]
    } else {
        section.data_range(start, end)?.to_vec()
    };
    Ok(ObjInfo::new(
        ObjKind::Relocatable,
        format!("padding_{start:08X}"),
        vec![],
        vec![ObjSection {
            name: format!("{}${start:08X}", section.name),
            kind: section.kind,
            original_flags: section.original_flags,
            size: end - start,
            data,
            align: 1,
            virtual_address: Some(start),
            ..Default::default()
        }],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obj::{ObjSplit, ObjSymbol, ObjSymbolKind, ObjUnit};
    use crate::util::{
        split::split_obj,
        xex::{write_coff, write_link_coff},
    };
    use object::{Object, ObjectSection};

    #[test]
    fn pe_raw_boundary_preserves_initialized_zeros_and_bss_symbols() -> Result<()> {
        let mut section = ObjSection {
            name: ".data".into(),
            kind: ObjSectionKind::Data,
            address: 0x1000,
            size: 0x400,
            data: vec![0; 0x400],
            align: 4,
            original_raw_size: Some(0x200),
            original_flags: Some(0xC0000040),
            ..Default::default()
        };
        section.splits.push(
            0x1000,
            ObjSplit {
                unit: "data".into(),
                end: 0x1400,
                ..Default::default()
            },
        );
        let mut image = ObjInfo::new(ObjKind::Executable, "bss".into(), vec![], vec![section]);
        image.link_order.push(ObjUnit {
            name: "data".into(),
            autogenerated: false,
            order: None,
        });
        image.symbols.add_direct(ObjSymbol {
            name: "zero_array".into(),
            address: 0x1300,
            section: Some(0),
            kind: ObjSymbolKind::Object,
            size: 0x100,
            size_known: true,
            ..Default::default()
        })?;
        let defaults = split_obj(&image, None)?;
        let before = write_coff(&defaults[0])?;
        let linked = link_objects(&image, &defaults)?;
        assert_eq!(before, write_coff(&defaults[0])?);
        let object = &linked[0];
        assert_eq!(object.sections[0].size, 0x200);
        assert_eq!(object.sections[1].name, ".dataz$00001200");
        assert_eq!(object.symbols[0].address, 0x100);
        assert_eq!(object.symbols[0].section, Some(1));
        let bytes = write_link_coff(object)?;
        let coff = object::File::parse(bytes.as_slice())?;
        let sections: Vec<_> = coff.sections().collect();
        assert_eq!(sections[0].data()?.len(), 0x200);
        assert_eq!(sections[1].size(), 0x200);
        assert!(sections[1].data()?.is_empty());
        Ok(())
    }
}
