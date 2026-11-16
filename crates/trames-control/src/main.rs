// SPDX-License-Identifier: GPL-3.0-or-later
use std::io;
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = if args.first().is_some_and(|s| s == "__file") {
        let result = (|| {
            let action = args
                .get(1)
                .ok_or_else(|| trames_control::Error::usage("Copy action required"))?;
            let path = std::path::Path::new(
                args.get(2)
                    .ok_or_else(|| trames_control::Error::usage("Copy path required"))?,
            );
            if action == "send" {
                trames_control::archive::send(path, io::stdout())
            } else if action == "receive" {
                let options = trames_control::copy::Options {
                    recursive: args.iter().any(|s| s == "-r"),
                    no_clobber: args.iter().any(|s| s == "-n"),
                    ..Default::default()
                };
                trames_control::archive::receive(io::stdin(), path, &options)
            } else {
                Err(trames_control::Error::usage("Unknown copy action"))
            }
        })();
        match result {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("trames: {e}");
                e.status
            }
        }
    } else {
        let mut backend = trames_control::guest::Guest::default();
        trames_control::run(&mut backend, &args, &mut io::stdout(), &mut io::stderr())
    };
    std::process::exit(code as i32);
}
