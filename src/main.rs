extern crate unicorn;
extern crate zydis;

use byteorder::{ByteOrder, LittleEndian};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use unicorn::{Cpu, CpuX86};
use zydis::gen::*;

fn align(value: usize, alignment: usize) -> usize {
    assert!(alignment.is_power_of_two());

    (value + (alignment - 1)) / alignment * alignment
}

fn check_mov_operands(ins: ZydisDecodedInstruction, image_base: u64) -> Option<usize> {
    if ins.operandCount != 2 {
        return None;
    }
    if ins.operandWidth != 32 {
        return None;
    }
    if ins.operands[0].type_ == ZYDIS_OPERAND_TYPE_REGISTER as u8 && ins.operands[0].reg.value == ZYDIS_REGISTER_EDI as u8 {
        if ins.operands[1].type_ == ZYDIS_OPERAND_TYPE_IMMEDIATE as u8 {
            let imm = ins.operands[1].imm.value.bindgen_union_field;
            if imm > image_base && imm < image_base + 16*1024*1024 {
                println!("end of compressed data likely before 0x{:x?}", imm);
                return Some(imm as usize - image_base as usize);
            }
        }
    }
    None
}

fn find_uncompressed_image_size(
    emu: &CpuX86,
    image_base: u64,
    image_size_aligned: usize,
) -> Option<usize> {
    let decoder = zydis::Decoder::new(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32).unwrap();
    let formatter = zydis::Formatter::new(ZYDIS_FORMATTER_STYLE_INTEL).unwrap();
    loop {
        let halted_eip = emu.reg_read(unicorn::RegisterX86::EIP).unwrap();
        let decompressed_program = emu.mem_read(halted_eip, 32).unwrap();
        let ins = decoder.decode(&decompressed_program, halted_eip).unwrap();
        if ins.is_some() {
            println!("{:x?} {}", halted_eip, formatter.format_instruction(&ins.unwrap(), 200, None).unwrap());
            if ins.unwrap().mnemonic == ZYDIS_MNEMONIC_MOV as u16 {
                let size = check_mov_operands(ins.unwrap(), image_base);
                if size.is_some() {
                    return size;
                }
            }
        }
        let step = emu.emu_start(halted_eip, image_base + image_size_aligned as u64, 0, 1);
        if step.is_err() {
                println!("Single stepping uncompressed code failed: {:?}", step.err());
                return None;
        }
    }
}
fn main() {
    let mut arguments = std::env::args();
    let in_filename = &arguments.nth(1).expect("Missing input filename");
    let out_filename = &arguments.nth(0).expect("Missing output filename");
    let mut in_f = File::open(in_filename).unwrap();
    let mut program = Vec::new();
    let len = align(in_f.read_to_end(&mut program).unwrap(), 4096);

    if LittleEndian::read_u16(&program[0..]) != LittleEndian::read_u16(b"MZ") {
        eprintln!(
            "{} is not a crinkled executable got {:#x?}",
            in_filename,
            &program[0..2]
        );
        std::process::exit(1);
    }

    let pe_offset = LittleEndian::read_u32(&program[0x3c..]) as usize;

    if &program[pe_offset..=pe_offset + 3] != b"PE\x00\x00" {
        eprintln!(
            "{} is not a crinkled executable got {:#x?}",
            in_filename,
            &program[pe_offset..=pe_offset + 3]
        );
        std::process::exit(1);
    }
    
    let mut section_alignment = LittleEndian::read_u32(&program[pe_offset + 0x38..]) as usize;
    if align(section_alignment, 4096) != section_alignment {
        section_alignment = 0;
    }

    let entry_point = LittleEndian::read_u32(&program[pe_offset + 0x28..]) as u64;
    let image_size = align(LittleEndian::read_u32(&program[pe_offset + 0x50..]) as usize, 4096);
    let image_base = LittleEndian::read_u32(&program[pe_offset + 0x34..]) as u64;
    let image_load_base = image_base + section_alignment as u64;
    let stack_size = align(LittleEndian::read_u32(&program[pe_offset + 0x64..]) as usize, 4096);
    let stack_base = image_base + align(image_size, 4096) as u64 + 0x20000;    

    eprintln!("Image: 0x{:08x}@0x{:08x}", image_size, image_base);
    if image_load_base != image_base {
        eprintln!("Load image: 0x{:08x}@0x{:08x}", len, image_load_base);
    }
    eprintln!("Entrypoint: 0x{:08x}", entry_point + image_base);
    eprintln!("Stack: 0x{:08}@0x{:08}", stack_size, stack_base);
  
    let emu = CpuX86::new(unicorn::Mode::MODE_32).expect("failed to instantiate unicorn");
    emu.mem_map(image_base, len, unicorn::Protection::ALL)
        .expect("failed to map image area");
    emu.mem_map(image_load_base + len as u64, image_size - len, 
        unicorn::Protection::READ | unicorn::Protection::WRITE)
        .expect("failed to map data area");
    emu.mem_write(image_base, &program).expect("failed to load program");
    if image_base != image_load_base {
        emu.mem_map(image_load_base, len, unicorn::Protection::ALL)
            .expect("failed to map image area at load base");
        emu.mem_write(image_load_base, &program).expect("failed to load program");
    }
    emu.mem_map(stack_base, stack_size,
        unicorn::Protection::READ | unicorn::Protection::WRITE,)
        .expect("failed to map stack");
    emu.reg_write(unicorn::RegisterX86::ESP, stack_base + stack_size as u64)
        .expect("failed to setup stack pointer");

    match emu.emu_start(image_base + entry_point, image_base + 0x20000, 0, 0) {
        Err(e) => {
            eprintln!(
                "{}. Emulator halted at 0x{:08x}",
                e,
                emu.reg_read(unicorn::RegisterX86::EIP).unwrap()
            );
        }
        Ok(_) => {
            eprintln!(
                "Emulation stopped at 0x{:08x}",
                emu.reg_read(unicorn::RegisterX86::EIP).unwrap()
            );
        }
    }

    let mut out_f = File::create(out_filename).unwrap();

    emu.mem_protect(image_load_base + len as u64, image_size - len, unicorn::Protection::ALL)
            .expect("failed to change memory protection");
    if image_load_base != image_base {
        emu.mem_map(image_base + len as u64, section_alignment - len, unicorn::Protection::READ)
            .expect("failed to change memory protection for section alignment area");
    }
    match find_uncompressed_image_size(&emu, image_base, image_size) {
        Some(size) => out_f
            .write_all(&emu.mem_read(image_base, size).unwrap())
            .unwrap(),
        _ => out_f
            .write_all(&emu.mem_read(image_base, image_size).unwrap())
            .unwrap(),
    };
}
