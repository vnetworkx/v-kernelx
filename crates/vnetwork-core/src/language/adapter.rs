use std::collections::BTreeMap;
use std::path::Path;
pub use v_langx::compiler::{
    compile_source_with_imports, CompiledOp, CompiledProgram, FilesystemModuleResolver,
    ImportedModuleRef, InMemoryModuleResolver, ModuleResolver, COMPILER_VERSION, LANGUAGE_VERSION,
};
pub use v_langx::error::{Diagnostic, RuntimeError, RuntimeErrorKind};
pub use v_langx::parser::parse;
use vnetwork_types::*;

pub fn compile_vx_source(
    source: &str,
    file_name: &str,
    inline_modules: &BTreeMap<String, String>,
    fs_base_dir: Option<&Path>,
) -> VResult<CompiledProgram> {
    let resolver = HybridModuleResolver {
        inline_modules,
        fs_base_dir,
    };
    compile_source_with_imports(source, file_name, &resolver).map_err(|e| {
        VNetworkError::Language(format!("{e}"))
    })
}

pub fn parse_vx_source(source: &str) -> VResult<serde_json::Value> {
    let program = parse(source)
        .map_err(|e| VNetworkError::Language(format!("{e}")))?;
    Ok(serde_json::json!({
        "statement_count": program.statements.len(),
        "valid": true,
    }))
}

struct HybridModuleResolver<'a> {
    inline_modules: &'a BTreeMap<String, String>,
    fs_base_dir: Option<&'a Path>,
}

impl<'a> ModuleResolver for HybridModuleResolver<'a> {
    fn resolve(&self, path: &str) -> Result<String, RuntimeError> {
        if let Some(src) = self.inline_modules.get(path) {
            return Ok(src.clone());
        }
        if let Some(dir) = self.fs_base_dir {
            let fs_res = FilesystemModuleResolver::new(dir);
            return fs_res.resolve(path);
        }
        Err(RuntimeError::new(RuntimeErrorKind::ImportError(format!(
            "module `{path}` was not provided in submission bundle or filesystem resolver"
        ))))
    }
}
