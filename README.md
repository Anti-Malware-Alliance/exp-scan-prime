# README

### Usage

Go to working directory of project, and run `cargo run -- /path/to/pe/file`.
The csv and parquet file will be placed in the `result` folder.

### Known issues

- Does not work on all PE files. currently only supportes 64-bit executables
- Does not print all information data directories as there can be different amounts
