use argh::FromArgs;
use std::{error::Error, fs, process::Command};
mod csv_builder;
mod extract;

#[derive(FromArgs)]
///Flags for feature extraction
struct AnalysisFlags {
    ///file or dir to print extracted elements to terminal
    #[argh(option, short = 'i')]
    inspect: Option<String>,

    /// files and dirs to extract features from
    #[argh(greedy, positional)]
    files: Vec<String>,
}

fn unpack_dir(dir_name: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut file_names: Vec<String> = vec![];

    let files = fs::read_dir(dir_name)?;

    for file in files {
        let file = file?;
        let path = file.path();
        let file_path = path.as_os_str().to_str().unwrap();
        let file_meta = fs::metadata(file_path)?;

        if file_meta.is_dir() {
            file_names.extend(unpack_dir(file_path)?);
        } else {
            file_names.push(file_path.to_owned());
        }
    }
    Ok(file_names)
}

fn collect_file_paths(file_names: &[String]) -> Result<Vec<String>, Box<dyn Error>> {
    let mut files = vec![];

    for name in file_names {
        if fs::metadata(name.as_str())?.is_file() {
            files.push(name.clone());
        } else if fs::metadata(name.as_str())?.is_dir() {
            files.extend(unpack_dir(name)?);
        }
    }
    Ok(files)
}

fn convert_csv_to_parquet(file_name: &str) {
    let _ = Command::new("python3")
        .args(["scripts/csv_to_parquet.py", file_name])
        .output()
        .expect("Failed to convert csv to parquet. Make sure `python3` is on your PATH");
}

fn inspect(file_name: &str) {
    let file_names = collect_file_paths(&[file_name.to_owned()]).unwrap();
    let (x64_head, x32_head) = (
        csv_builder::get_x64_headers(),
        csv_builder::get_x32_headers(),
    );
    let (x64_rows, x32_rows) = csv_builder::build_csv_rows(&file_names);
    for r in x64_rows {
        print_inspect(x64_head.as_str(), r.as_str());
    }
    for r in x32_rows {
        print_inspect(x32_head.as_str(), r.as_str());
    }
}

fn print_inspect(header: &str, data: &str) {
    let head_vec: Vec<&str> = header.split(",").collect();
    let dat_vec: Vec<&str> = data.split(",").collect();

    for i in 0..head_vec.len() {
        println!("{}: {}", head_vec[i], dat_vec[i]);
    }
    println!();
}

fn main() -> Result<(), Box<dyn Error>> {
    let inspect_arg: AnalysisFlags = argh::from_env();
    if let Some(file_name) = inspect_arg.inspect {
        inspect(file_name.as_str());
    }

    let mut args = inspect_arg.files.clone();
    args.retain(|s| fs::metadata(s).is_ok());

    let files = collect_file_paths(&args)?;

    let (x64, x32) = csv_builder::extract_to_csv(&files);
    convert_csv_to_parquet(x64.as_str());
    convert_csv_to_parquet(x32.as_str());

    Ok(())
}
