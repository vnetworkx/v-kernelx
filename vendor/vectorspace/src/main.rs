use std::env;
use std::fs;
use std::process::ExitCode;

use v_langx::runtime::Runtime;

fn main() -> ExitCode {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let mut show_ast = false;
    let mut show_events = false;

    args.retain(|arg| match arg.as_str() {
        "--ast" => {
            show_ast = true;
            false
        }
        "--events" => {
            show_events = true;
            false
        }
        _ => true,
    });

    let path = match args.first() {
        Some(path) => path,
        None => {
            eprintln!("usage: v-langx [--ast] [--events] <file.vx|file.vdx>");
            return ExitCode::from(2);
        }
    };

    let source = match fs::read_to_string(path) {
        Ok(src) => src,
        Err(err) => {
            eprintln!("failed to read {path}: {err}");
            return ExitCode::from(1);
        }
    };

    let mut runtime = Runtime::new();

    if show_ast {
        match runtime.parse(&source) {
            Ok(program) => {
                println!("{:#?}", program);
                return ExitCode::SUCCESS;
            }
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        }
    }

    match runtime.execute_source(&source) {
        Ok(report) => {
            for output in report.outputs {
                println!("{output}");
            }
            if show_events {
                for event in report.final_state.events {
                    println!("{event}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}
