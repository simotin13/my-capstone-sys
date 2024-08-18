
use my_capstone_sys::cs_open;
use my_capstone_sys::cs_disasm;
use my_capstone_sys::cs_free;
use my_capstone_sys::cs_insn;
use std::ffi::CStr;
use std::ptr;
use my_capstone_sys::csh;
use my_capstone_sys::cs_arch_CS_ARCH_X86;
use my_capstone_sys::cs_mode_CS_MODE_64;

fn disassemble_x86(code: &[u8]) {
    // Capstoneのハンドルを保持する変数
    let mut handle: csh = 0;
    // Capstoneの初期化
    unsafe {
        let arch = cs_arch_CS_ARCH_X86; // CS_ARCH_X86の値
        let mode = cs_mode_CS_MODE_64; // CS_MODE_64の値
        let result = cs_open(arch, mode, &mut handle);
        if result != 0 {
            eprintln!("Failed to initialize Capstone");
            return;
        }
    }

    let mut insn_ptr: *mut cs_insn = ptr::null_mut();
    let code_size = code.len();
    let count = unsafe {
        cs_disasm(handle, code.as_ptr(), code_size, 0x1000, 0, &mut insn_ptr)
    };

    if count > 0 {
        unsafe {
            for i in 0..count {
                let insn = *insn_ptr.add(i);
                let mnemonic_ptr = insn.mnemonic.as_ptr();
                let mnemonic = CStr::from_ptr(mnemonic_ptr).to_str().unwrap_or("?");

                let op_str_ptr = insn.op_str.as_ptr();
                let op_str = CStr::from_ptr(op_str_ptr).to_str().unwrap_or("?");
                println!("0x{:x}:\t{}\t{}", insn.address, mnemonic, op_str);
            }
            cs_free(insn_ptr, count);
        }
    } else {
        println!("Disassembly failed");
    }

}
fn main() {
    println!("Hello, world!");

    let mut handle: csh = 0;
    let code: &[u8] = &[0x90, 0x90, 0x90];

    // x86コードのディスアセンブル
    disassemble_x86(code);
}
