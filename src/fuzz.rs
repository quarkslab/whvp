
use std::mem;
use std::cmp;
use std::time::Instant;
use std::time::Duration;

use std::collections::HashMap;

use rand::SeedableRng;
use rand::rngs::StdRng;

use lain::prelude::*;
use lain::rand;
use lain::hexdump;

use ni_rs;

pub fn convert(num: f64) -> String {
    let negative = if num.is_sign_positive() { "" } else { "-" };
    let num = num.abs();
    let units = ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    if num < 1_f64 {
        return format!("{}{} {}", negative, num, "B");
    }
    let delimiter = 1000_f64;
    let exponent = cmp::min((num.ln() / delimiter.ln()).floor() as i32, (units.len() - 1) as i32);
    let pretty_bytes = format!("{:.2}", num / delimiter.powi(exponent)).parse::<f64>().unwrap() * 1_f64;
    let unit = units[exponent as usize];
    format!("{}{} {}", negative, pretty_bytes, unit)
}

#[derive(Debug)]
pub struct Stats {
    pub iterations: u64,
    pub total_iterations: u64,
    pub coverage: u64,
    pub total_coverage: u64,
    pub code: u64,
    pub data: u64,
    pub start: Instant,
    pub total_start: Instant,
    interval: Duration,
}

impl Stats {

    pub fn new(interval: Duration) -> Self {
        let start = Instant::now();
        Stats {
            iterations: 0,
            total_iterations: 0,
            coverage: 0,
            total_coverage: 0,
            code: 0,
            data: 0,
            start: start,
            total_start: start,
            interval: interval
        }
    }

    pub fn reset(&mut self) {
        self.iterations = 0;
        self.coverage = 0;
        self.start = Instant::now()
    }

    pub fn display(&mut self) {
        if self.start.elapsed() > self.interval {
            println!("{} executions, {} exec/s, coverage {}, new {}, code {}, data {}",
                self.total_iterations,
                self.iterations / self.interval.as_secs(),
                self.total_coverage,
                self.coverage,
                convert((self.code * 0x1000) as f64),
                convert((self.data * 0x1000) as f64));
            self.reset();
        }
    }
}

pub struct Params {

    pub max_iterations: u64,
    pub max_duration: Duration,
    pub input: u64,
    pub input_size: u64,
    pub input_type: InputType
}

pub enum InputType {
    Mem,
    Reg
}

#[derive(Debug, Default, Clone, Mutatable, NewFuzzed, BinarySerialize)]
struct FuzzerInput {
    // data: Vec<u8>
    // data: [u8; 32],
    // #[lain(min = 1, max = 50)]
    // data: Vec<u8>,
    #[lain(min = 0, max = 2000)]
    size: u16,
}

// impl FuzzerInput {

//     pub fn new() -> Self {
//         FuzzerInput {
//             data: Vec::new()
//         }
//     }
// }

#[derive(Default, Debug)]
struct FuzzerContext {
    input: Option<FuzzerInput>,
    scratch: FuzzerInput,
    iterations: usize,
}


pub struct Corpus {
    queue: HashMap<u64, Vec<u8>>,
    mutator: Mutator<StdRng>,
    context: FuzzerContext,
    min: u64,
    max: u64,
    max_size: usize

}

impl Corpus {

    pub fn new(min: u64, max: u64, max_size: usize) -> Self {
        let thread_rng = StdRng::seed_from_u64(0u64);
        let mut mutator = Mutator::new(thread_rng);
        mutator.begin_new_corpus();

        let mut context = FuzzerContext::default();

        // context.scratch = FuzzerInput::new_fuzzed(&mut mutator, Some(constraints));

        Corpus {
            queue: HashMap::new(),
            mutator: mutator,
            context: context,
            min: min,
            max: max,
            max_size: max_size
        }
    }

    // FIXME: select input

    pub fn get_serialized_input(&mut self) -> Vec<u8> {
            // let packet = match fuzzer_context.input {
            //     Some(ref mut input) => {
            //         if mutator.mode() == MutatorMode::Havoc {
            //             input.mutate(&mut mutator, None);
            //             input
            //         } else {
            //             fuzzer_context.scratch = input.clone();
            //             fuzzer_context.scratch.mutate(&mut mutator, None);
            //             &fuzzer_context.scratch
            //         }
            //     },
            //     _ => {
            //         mutator.begin_new_corpus();
            //         fuzzer_context.input = Some(FuzzerInput::new_fuzzed(&mut mutator, None));
            //         fuzzer_context.input.as_mut().unwrap()
            //     }
            // };

            self.mutator.begin_new_iteration();
            let mut constraints = Constraints::new();
            constraints.max_size(self.max_size);
            self.context.scratch.mutate(&mut self.mutator, Some(&constraints));
            let mut serialized_data = Vec::with_capacity(self.context.scratch.serialized_size());
            self.context.scratch.binary_serialize::<_, LittleEndian>(&mut serialized_data);
            serialized_data

            // context.rdx.Reg64 = fuzzer_context.scratch.size.into();
            // println!("iteration {} mode {:?} {:?}", fuzzer_context.iterations, mutator, fuzzer_context.scratch);
            // println!("{:?}", packet);
            // println!("\n{}", hexdump(&serialized_data));
    }

    // pub fn get_input(&mut self) -> u64 {
        // self.mutator.begin_new_iteration();
        // let mut constraints = Constraints::new();
        // constraints.min(self.min);
        // constraints.max(self.max);
        // constraints.max_size(self.max_size);

        // self.context.scratch.mutate(&mut self.mutator, Some(&constraints));
        // self.context.scratch.mutate(&mut self.mutator, None);
        // self.context.scratch.size.into()
    // }

    pub fn get_input(&mut self) -> u64 {
        let mut rng = rand::thread_rng();
        // let input = rng.gen::<u64>();
        let input = rng.gen_range(self.min, self.max);
        input
        // let input = 0u64;
        // return input.arbitrary()
        // let mut buf = [0; mem::size_of::<u64>()];
        // let mutation = ni_rs::mutate(buf.to_vec());
        // mutation
    }
}
