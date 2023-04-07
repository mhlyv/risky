mod elf;

fn main() {
    // let path = std::env::args().nth(1).expect("excpected filename");
    let path = "samples/exit";

    let elf = elf::read_elf(path).unwrap();

    println!("{:#?}", elf);
}
