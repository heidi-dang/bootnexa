#![no_std]
#![no_main]
// Licensed synthetic open-source UEFI smoke fixture; writes a marker only
// to QEMU's emulated ISA debug output port. No disk, firmware state, or
// external peripheral is modified. UEFI execution, not Windows setup.
use core::panic::PanicInfo;
#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop { core::hint::spin_loop(); } }

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle:usize,_system_table:usize)->usize {
    for byte in b"BOOTNEXA_UEFI_BOOT_OK\n" {
        unsafe {
            core::arch::asm!("out dx, al",
                in("dx") 0xe9u16,in("al") *byte,
                options(nomem,nostack,preserves_flags));
        }
    }
    0 // EFI_SUCCESS
}
