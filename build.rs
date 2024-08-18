fn main() {
    println!("cargo:rustc-link-lib=capstone");
    let bindings = bindgen::Builder::default()
        .header("binding.h")
        .ctypes_prefix("cty")
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file("src/bindings.rs")
        .expect("Couldn't write bindings!");
}