use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Get tree-sitter include path from the tree-sitter crate
    let tree_sitter_dir = PathBuf::from(
        std::env::var("DEP_TREE_SITTER_RUNTIME_INCLUDE").unwrap_or_else(|_|
            // Fallback to a common location if the env var is not set
            format!("{}/target/debug/build/tree-sitter-*/out", dir.display())
        ),
    );

    // Compile tree-sitter parsers
    println!("cargo:rerun-if-changed=build.rs");

    // Helper function to add appropriate warning suppressions based on compiler
    fn add_warning_suppressions(build: &mut cc::Build) {
        if build.get_compiler().is_like_msvc() {
            // MSVC compiler: suppress warnings
            build.flag("/wd4100"); // C4100: unused parameter
            build.flag("/wd4505"); // C4505: unused function
        } else {
            // GCC/Clang: suppress warnings
            build.flag("-Wno-unused-parameter");
            build.flag("-Wno-unused-function");
        }
    }

    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .file(dir.join("tree-sitter-c/src/parser.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-c");

    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .file(dir.join("tree-sitter-cpp/src/parser.c"))
        .file(dir.join("tree-sitter-cpp/src/scanner.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-cpp");

    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .file(dir.join("tree-sitter-go/src/parser.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-go");

    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .file(dir.join("tree-sitter-java/src/parser.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-java");

    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .file(dir.join("tree-sitter-javascript/src/parser.c"))
        .file(dir.join("tree-sitter-javascript/src/scanner.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-javascript");

    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .file(dir.join("tree-sitter-python/src/parser.c"))
        .file(dir.join("tree-sitter-python/src/scanner.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-python");

    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .file(dir.join("tree-sitter-rust/src/parser.c"))
        .file(dir.join("tree-sitter-rust/src/scanner.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-rust");

    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .include(dir.join("tree-sitter-typescript/typescript/src"))
        .include(dir.join("tree-sitter-typescript/common"))
        .file(dir.join("tree-sitter-typescript/typescript/src/parser.c"))
        .file(dir.join("tree-sitter-typescript/typescript/src/scanner.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-typescript");

    // Add build step for TSX parser
    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .include(dir.join("tree-sitter-typescript/tsx/src"))
        .include(dir.join("tree-sitter-typescript/common"))
        .file(dir.join("tree-sitter-typescript/tsx/src/parser.c"))
        .file(dir.join("tree-sitter-typescript/tsx/src/scanner.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-tsx");

    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .file(dir.join("tree-sitter-ruby/src/parser.c"))
        .file(dir.join("tree-sitter-ruby/src/scanner.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-ruby");

    // Add HCL/Terraform parser
    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .file(dir.join("tree-sitter-terraform/src/parser.c"))
        .file(dir.join("tree-sitter-terraform/src/scanner.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-hcl");

    // Add PHP parser
    let mut build = cc::Build::new();
    build.include(&dir)
        .include(&tree_sitter_dir)
        .include(dir.join("tree-sitter-php/php/src"))
        .include(dir.join("tree-sitter-php/common"))
        .file(dir.join("tree-sitter-php/php/src/parser.c"))
        .file(dir.join("tree-sitter-php/php/src/scanner.c"));
    add_warning_suppressions(&mut build);
    build.compile("tree-sitter-php");

    // TODO: Add YAML and Bash support once tree-sitter submodules are properly set up
    // cc::Build::new()
    //     .include(&dir)
    //     .include(&tree_sitter_dir)
    //     .include(dir.join("tree-sitter-yaml/src"))
    //     .file(dir.join("tree-sitter-yaml/src/parser.c"))
    //     .file(dir.join("tree-sitter-yaml/src/scanner.cc"))
    //     .flag("-Wno-unused-parameter")
    //     .cpp(true)
    //     .compile("tree-sitter-yaml");

    // cc::Build::new()
    //     .include(&dir)
    //     .include(&tree_sitter_dir)
    //     .include(dir.join("tree-sitter-bash/src"))
    //     .file(dir.join("tree-sitter-bash/src/parser.c"))
    //     .file(dir.join("tree-sitter-bash/src/scanner.c"))
    //     .flag("-Wno-unused-parameter")
    //     .compile("tree-sitter-bash");

    // Add library search path
    println!("cargo:rustc-link-search=native={}", out_dir.display());
}
