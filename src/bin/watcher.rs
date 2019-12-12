
use crossbeam_channel::unbounded;
use notify::{RecommendedWatcher, RecursiveMode, Result, Watcher};


fn watch() -> Result<()> {
    // Create a channel to receive the events.
    let (tx, rx) = unbounded();

    // Automatically select the best implementation for your platform.
    let mut watcher: RecommendedWatcher = Watcher::new_immediate(tx)?;

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher.watch(".", RecursiveMode::NonRecursive)?;

    loop {
        match rx.recv() {
           Ok(event) => println!("changed: {:?}", event),
           Err(err) => {
               println!("watch error: {:?}", err);
               break;
           }
        };
    }

    Ok(())
}

fn main() {

}
