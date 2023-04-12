mod elf;
mod vm;

use vm::VirtualMemory;

#[derive(Debug)]
pub enum Error {
    Memory(vm::Error),
}

type Word = u32;
type Instruction = u32;

#[derive(Debug)]
pub struct Machine {
    memory: VirtualMemory,
    registers: [u64; 32],
    pc: u64,
}

impl Machine {
    fn read_word(&self, address: u64) -> Result<Word, Error> {
        let mut buf = [0; 4];
        self.memory
            .read_slice(self.pc as _, &mut buf)
            .map_err(Error::Memory)?;

        Ok(Word::from_le_bytes(buf))
    }

    /// fetch an instruction from pc
    /// only supports the 32 bit instructions for now
    fn fetch_instruction(&self) -> Result<Instruction, Error> {
        let word = self.read_word(self.pc)?;
        Ok(word)
    }

    pub fn cycle(&mut self) -> Result<(), Error> {
        let instruction = self.fetch_instruction()?;

        let opcode = instruction & 0b111_1111;
        let funct3 = (instruction >> 12) & 0b111;
        let imm11_0 = instruction >> 20;
        let rd = ((instruction >> 7) & 0b1_1111) as usize;
        let rs1 = ((instruction >> 15) & 0b1_1111) as usize;

        println!(
            "instr : {} {:#x} {:#b}",
            instruction, instruction, instruction
        );
        println!("opcode: {} {:#x} {:#b}", opcode, opcode, opcode);
        println!("funct3: {} {:#x} {:#b}", funct3, funct3, funct3);
        println!("imm110: {} {:#x} {:#b}", imm11_0, imm11_0, imm11_0);
        println!("rd    : {} {:#x} {:#b}", rd, rd, rd);
        println!("rs1   : {} {:#x} {:#b}", rs1, rs1, rs1);

        match (funct3, opcode) {
            (0, 0b0010011) => {
                // ADDI
                self.registers[rd] = self.registers[rs1].wrapping_add(imm11_0 as _);
            }
            (0, 0b1110011) => {
                match imm11_0 {
                    0 => {
                        // ECALL
                        match self.registers[17] {
                            93 => {
                                std::process::exit(self.registers[10].try_into().unwrap());
                            }
                            _ => unimplemented!(),
                        }
                    }
                    _ => unimplemented!(),
                }
            }
            _ => unimplemented!(),
        }

        // TODO: only works for 32 bit instructions
        self.pc += 4;

        Ok(())
    }
}

fn main() {
    // let path = std::env::args().nth(1).expect("excpected filename");
    let path = "samples/nostd/target/riscv64gc-unknown-linux-gnu/release/nostd";

    let elf = elf::read_elf(path).unwrap();

    let segments = elf.segments.into_iter();
    let vm = VirtualMemory::try_from_iter(segments).unwrap();

    println!("{:#?}", vm);

    let mut machine = Machine {
        memory: vm,
        registers: Default::default(),
        pc: elf.entry.into(),
    };

    machine.cycle().unwrap();
    machine.cycle().unwrap();

    println!("{:?}", machine.registers);

    machine.cycle().unwrap();
}
