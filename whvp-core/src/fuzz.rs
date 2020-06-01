
use std::convert::TryInto;
use std::cmp;
use std::time::Duration;
use std::time::Instant;

use std::io::{BufWriter, Write};

use std::thread;
use std::sync::mpsc;

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use serde::{Serialize, Deserialize};
use serde_json;

use anyhow::Result;

use ni_rs;

use crate::trace;
use crate::watch;


pub fn convert(num: f64) -> String {
    let negative = if num.is_sign_positive() { "" } else { "-" };
    let num = num.abs();
    let units = ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    if num < 1_f64 {
        return format!("{}{} {}", negative, num, "B");
    }
    let delimiter = 1000_f64;
    let exponent = cmp::min(
        (num.ln() / delimiter.ln()).floor() as i32,
        (units.len() - 1) as i32,
    );
    let pretty_bytes = format!("{:.2}", num / delimiter.powi(exponent))
        .parse::<f64>()
        .unwrap()
        * 1_f64;
    let unit = units[exponent as usize];
    format!("{}{} {}", negative, pretty_bytes, unit)
}

#[derive(Debug)]
pub struct Stats {
    pub iterations: u64,
    pub total_iterations: u64,
    pub coverage: u64,
    pub total_coverage: u64,
    pub code: usize,
    pub data: usize,
    pub start: Instant,
    pub total_start: Instant,
    interval: Duration,
    pub corpus_size: usize,
    pub worklist_size: usize,
    pub crashes: u64,
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
            interval: interval,
            corpus_size: 0,
            worklist_size: 0,
            crashes: 0,
        }
    }

    pub fn reset(&mut self) {
        self.iterations = 0;
        self.coverage = 0;
        self.start = Instant::now()
    }

    pub fn update_display(&mut self) {
        if self.start.elapsed() > self.interval {
            self.display();
        }
    }
    pub fn display(&mut self) {
        info!("{} executions, {} exec/s, coverage {}, new {}, code {}, data {}, corpus {}, crashes {}",
            self.total_iterations,
            self.iterations / self.interval.as_secs(),
            self.total_coverage,
            self.coverage,
            convert((self.code * 0x1000) as f64),
            convert((self.data * 0x1000) as f64),
            self.corpus_size,
            self.crashes);
        self.reset();
    }
}


#[derive(Default, Serialize, Deserialize, CustomDebug)]
pub struct CrashParams {
    pub input: u64,
    pub input_size: u64,
}

impl From<&Params> for CrashParams {

    fn from(params: &Params) -> Self {
        Self {
            input: params.input,
            input_size: params.input_size,
        }
    }
}


#[derive(Default)]
pub struct Params {
    pub max_iterations: u64,
    pub max_duration: Duration,
    pub input: u64,
    pub input_size: u64,
    pub stop_on_crash: bool,
    pub display_delay: Duration,
}

pub struct Corpus {
    workdir: String,
    pub queue: HashMap<usize, Vec<u8>>,
    pub worklist: Vec<Vec<u8>>,
    pub coverage: HashSet<u64>,
}

impl Corpus {
    pub fn new(workdir: &str) -> Self {
        // FIXME: check if corpus and crashes directories are created
        // FIXME: queue, coverage and worklist should be in Strategy
        Corpus {
            workdir: workdir.to_string(),
            queue: HashMap::new(),
            worklist: Vec::new(),
            coverage: HashSet::new(),
        }
    }

    pub fn load(&mut self) -> Result<usize> {
        let path = Path::new(&self.workdir).join("corpus");
        let paths = fs::read_dir(path)?;
        let mut total = 0;
        for path in paths {
            let path = path?.path();
            if path.extension() == Some(OsStr::new("bin")) {
                let mut file = File::open(&path)?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                fs::remove_file(path)?;
                self.worklist.push(data);
                total += 1;
            }
        }

        Ok(total)
    }

    pub fn add(&mut self, coverage: usize, input: &Vec<u8>) -> Result<()> {
        self.queue.insert(coverage, input.to_vec());
        let hash = calculate_hash(&input);
        let path = Path::new(&self.workdir)
            .join("corpus")
            .join(format!("{:x}.bin", hash));
        let mut file = File::create(path)?;
        file.write_all(&input)?;
        Ok(())
    }

}

pub fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

pub trait Strategy {

    fn mutate_input(&mut self, input: &Vec<u8>) -> Vec<u8>;

    fn get_next_input(&mut self, corpus: &mut Corpus) -> Option<Vec<u8>>;

    fn apply(&mut self, params: &Params, data: &Vec<u8>, trace: &trace::Trace, corpus: &mut Corpus) -> Result<usize>;

}

pub struct RandomStrategy {

}

impl RandomStrategy {
    pub fn new() -> Self {
        RandomStrategy {
        }
    }

}

impl Strategy for RandomStrategy {

    fn mutate_input(&mut self, input: &Vec<u8>) -> Vec<u8> {
        let mutation = ni_rs::mutate(input.to_vec());
        mutation
    }

    fn get_next_input(&mut self, corpus: &mut Corpus) -> Option<Vec<u8>> {
        if let Some(item) = corpus.worklist.pop() {
            return Some(item);
        }

        for item in corpus.queue.values() {
            corpus.worklist.push(item.to_vec());
        }

        corpus.worklist.pop()
    }

    fn apply(&mut self, fuzz_params: &Params, data: &Vec<u8>, trace: &trace::Trace, corpus: &mut Corpus) -> Result<usize> {
        let mut new = 0;
        for addr in trace.seen.iter() {
            if corpus.coverage.insert(*addr) {
                new += 1;
            }
        }

        if new > 0 {
            info!("discovered {} new address(es), adding file to corpus", new);
            corpus.add(new, data)?;
        }

        match trace.status {
            trace::EmulationStatus::ForbiddenAddress => {
                let hash = calculate_hash(data);
                let path = Path::new(&corpus.workdir)
                    .join("crashes")
                    .join(format!("{:x}.bin", hash));
                info!("got abnormal exit, saving input to {:?}", path);
                let mut file = File::create(path)?;
                file.write_all(data)?;

                let params: CrashParams = fuzz_params.into();
                let path = Path::new(&corpus.workdir)
                    .join("crashes")
                    .join(format!("{:x}.json", hash));
                let mut fp = BufWriter::new(std::fs::File::create(path)?);
                let data = serde_json::to_vec_pretty(&params)?;
                fp.write_all(&data)?;

            }
            _ => {

            }
        }

        Ok(new)

    }

}

pub struct Fuzzer {
    path: String,
    channel: mpsc::Receiver<Vec<u8>>,
}

impl Fuzzer {
    // FIXME: https://www.philipdaniels.com/blog/2019/rust-api-design/
    pub fn new<S>(path: S) -> Result<Self>
    where S: Into<String> {
        let (tx, rx) = mpsc::channel();

        let fuzzer = Fuzzer {
            path: path.into(),
            channel: rx,
        };

        let copy = fuzzer.path.clone();
        let _thread = thread::spawn(move || watch::watch(tx, &copy));

        Ok(fuzzer)
    }

    pub fn run<T: trace::Tracer, S: Strategy>(&mut self, strategy: &mut S, params: &Params, tracer: &mut T, context: &trace::ProcessorState, trace_params: &trace::Params) -> Result<Stats> {
        let mut stats = Stats::new(params.display_delay);

        let mut corpus = Corpus::new(&self.path);
        let files = corpus.load()?;
        info!("loaded {} file(s) to corpus", files);

        info!("first execution to map memory");

        tracer.set_initial_context(&context)?;
        let trace = tracer.run(trace_params)?;
        match trace.status {
            trace::EmulationStatus::Success => {
            }
            _ => {
                return Err(anyhow!("first execution failed!"))
            }
        }

        info!("reading input");
        let input_size: usize = params.input_size.try_into()?;
        let mut data = Vec::with_capacity(input_size);
        data.resize(input_size, 0);

        let cr3 = tracer.cr3()?;
        tracer.read_gva(cr3, params.input, &mut data)?;

        info!("add first trace to corpus");
        strategy.apply(&params, &data, &trace, &mut corpus)?;

        info!("start fuzzing");

        loop {
            match self.channel.try_recv() {
                Ok(data) => {
                    info!("add file to worklist");
                    corpus.worklist.push(data);
                }
                _ => {}
            }

            let data: Vec<u8> = match strategy.get_next_input(&mut corpus) {
                None => {
                    error!("no more input, stop");
                    return Err(anyhow!("corpus is empty"));
                }
                Some(data) => data,
            };

            let mut input = strategy.mutate_input(&data);
            input.truncate(input_size);

            match tracer.write_gva(cr3, params.input, &input) {
                Ok(()) => {}
                Err(e) => {
                    error!("can't write fuzzer input {:?}", e);
                    return Err(anyhow!("can't write fuzzer input"));
                }
            }

            tracer.set_initial_context(&context)?;
            tracer.restore_snapshot()?;

            let trace = tracer.run(trace_params)?;

            let new = strategy.apply(&params, &input, &trace, &mut corpus)?;

            match trace.status {
                trace::EmulationStatus::ForbiddenAddress => {
                    stats.crashes += 1;
                    if params.stop_on_crash {
                        break;
                    }
                }
                _ => {}
            }

            stats.iterations += 1;
            stats.total_iterations += 1;

            stats.coverage += new as u64;
            stats.total_coverage = corpus.coverage.len() as u64;

            stats.code = tracer.get_code_pages();
            stats.data = tracer.get_data_pages();

            stats.corpus_size = corpus.queue.len();
            stats.worklist_size = corpus.worklist.len();

            stats.update_display();

            if params.max_duration.as_secs() != 0 && stats.total_start.elapsed() > params.max_duration {
                break;
            }

            if params.max_iterations != 0 && stats.total_iterations > params.max_iterations {
                break;
            }

        }
        info!("fuzzing session ended after {:?} and {} iteration(s)", stats.total_start.elapsed(), stats.total_iterations);
        Ok(stats)
    }
}

