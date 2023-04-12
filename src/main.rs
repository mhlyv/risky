mod elf;
mod vm;

use vm::VirtualMemory;

fn main() {
    // let path = std::env::args().nth(1).expect("excpected filename");
    let path = "samples/nostd/target/riscv64gc-unknown-linux-gnu/debug/nostd";

    let elf = elf::read_elf(path).unwrap();

    let segments = elf.segments.into_iter();
    let vm = VirtualMemory::try_from_iter(segments).unwrap();

    println!("{:#?}", vm);

    let mut buf = [0; 4];
    vm.read_slice(elf.entry.into(), &mut buf).unwrap();
    println!("{:x?}", buf);
}
