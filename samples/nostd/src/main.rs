#![no_std]
#![no_main]
#![feature(lang_items)]

use core::arch::asm;

#[lang = "eh_personality"]
fn eh_personality() {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

fn exit(status: i32) -> ! {
    let syscall = 93;
    unsafe {
        asm!(
            "ecall",
            in("a0") status,
            in("a7") syscall,
            options(noreturn)
        )
    }
}

#[no_mangle]
pub fn _start() {
    exit(0);
}
