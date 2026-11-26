use std::path::PathBuf;
use v_langx::compiler::{compile_source_with_imports, FilesystemModuleResolver};

pub fn run_language_check(file: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let src = std::fs::read_to_string(&file)?;
    let dir = file.parent().unwrap_or_else(|| std::path::Path::new("."));
    let resolver = FilesystemModuleResolver::new(dir);
    let fname = file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("program.vx");
    let compiled = compile_source_with_imports(&src, fname, &resolver)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "valid": true,
            "file": fname,
            "language_version": compiled.language_version,
            "compiler_version": compiled.compiler_version,
            "source_hash": compiled.source_hash,
            "program_hash": compiled.program_hash,
            "imported_modules": compiled.imported_modules,
            "op_count": compiled.ops.len(),
            "diagnostics": compiled.diagnostics,
        }))?
    );
    Ok(())
}

pub fn run_language_compile(file: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let src = std::fs::read_to_string(&file)?;
    let dir = file.parent().unwrap_or_else(|| std::path::Path::new("."));
    let resolver = FilesystemModuleResolver::new(dir);
    let fname = file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("program.vx");
    let compiled = compile_source_with_imports(&src, fname, &resolver)?;
    println!("{}", serde_json::to_string_pretty(&compiled)?);
    Ok(())
}
