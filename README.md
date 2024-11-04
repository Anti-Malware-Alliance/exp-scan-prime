# README

### Usage

Go to working directory of project, and run `cargo run -- /path/to/pe/file`.
The csv and parquet file will be placed in the `result` folder.

To inspect a single file or directory, use the `-inspect` or `-i` option.

Such as `cargo run -- -i some_file.exe other_file.exe`. some_file.exe will be
extracted and printed to the terminal, and NOT added to the csv

Currently only works on POSIX compliant systems (UNIX, Linux, MacOS, etc.)
