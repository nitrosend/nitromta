//! The engine's own binary, whose name is the product's: the
//! engine with no hooks.

fn main() -> std::process::ExitCode {
    engine::main(engine::Hooks::default())
}
