
use std::cmp;
use std::time::Instant;
use std::time::Duration;

use std::collections::HashMap;

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

    pub fn check_display(&mut self) {
        if self.start.elapsed() > self.interval {
            self.display();
        }
    }
    pub fn display(&mut self) {
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

pub struct Corpus {
    queue: HashMap<usize, Vec<u8>>,
    pub worklist: Vec<Vec<u8>>,
}

impl Corpus {

    pub fn new() -> Self {
        Corpus {
            queue: HashMap::new(),
            worklist: Vec::new(),
        }
    }

    pub fn mutate_input(&mut self, input: &Vec<u8>) -> Vec<u8> {
        let mutation = ni_rs::mutate(input.to_vec());
        mutation
    }

    pub fn add(&mut self, coverage: usize, input: &Vec<u8>) -> () {
        self.queue.insert(coverage, input.to_vec());
    }

    pub fn get_next_input(&mut self) -> Option<Vec<u8>> {
        if let Some(item) = self.worklist.pop() {
            return Some(item);
        }

        for item in self.queue.values() {
            self.worklist.push(item.to_vec());
        }

        self.worklist.pop()
    }

    pub fn display(&mut self) {
        println!("{} items in corpus",
            self.queue.len());
    }

}
