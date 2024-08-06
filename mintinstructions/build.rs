use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/unlock_proto.proto"], &["src"])?;
    Ok(())
}
