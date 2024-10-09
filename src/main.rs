use std::{
    env,
    error::Error,
    fs::{self, File},
    io::Write,
    process::Command,
    str,
};

use exe::pe::{VecPE, PE};
mod pe_collector;
mod pe_imports;

#[derive(Debug)]
enum ArgError {
    InvalidArgNum,
    InvalidFileName,
}

fn get_valid_arg() -> Result<String, ArgError> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        return Err(ArgError::InvalidArgNum);
    }

    if fs::metadata(args[1].as_str()).is_err() {
        return Err(ArgError::InvalidFileName);
    }

    Ok(args[1].clone())
}

fn build_csv_64(file_name: &str, image: &VecPE) -> Result<String, Box<dyn Error>> {
    let row = format!("{},{}", file_name, pe_collector::parse_64(image)?);

    let csv_header = pe_collector::get_csv_headers_64();

    let csv_path = "result/sample64.csv";
    {
        // controllin the scope of the file to make sure it closed before the script is called
        let mut f = File::create(csv_path).expect("Unable to create file");
        f.write_all(format!("{}\n{}", csv_header, row).as_bytes())
            .expect("Unable to write data");
    }

    Ok(csv_path.to_owned())
}

fn build_csv_32(file_name: &str, image: &VecPE) -> Result<String, Box<dyn Error>> {
    let row = format!("{},{}", file_name, pe_collector::parse_32(image)?);

    let csv_header = pe_collector::get_csv_headers_32();

    let csv_path = "result/sample32.csv";
    {
        // controllin the scope of the file to make sure it closed before the script is called
        let mut f = File::create(csv_path).expect("Unable to create file");
        f.write_all(format!("{}\n{}", csv_header, row).as_bytes())
            .expect("Unable to write data");
    }

    Ok(csv_path.to_owned())
}

fn main() -> Result<(), Box<dyn Error>> {
    let file_name = get_valid_arg().unwrap();

    let image = VecPE::from_disk_file(file_name.clone())?;

    let is_64_bit: bool = image.get_arch()? == exe::Arch::X64;

    let file_path = if is_64_bit {
        build_csv_64(file_name.as_str(), &image)?
    } else {
        build_csv_32(file_name.as_str(), &image)?
    };

    let out = Command::new("python3")
        .args(["scripts/csv_to_parquet.py", file_path.as_str()])
        .output()
        .expect("Failed to convert csv to parquet. Make sure `python3` is on your PATH");

    println!("{}", str::from_utf8(out.stdout.as_slice())?);
    println!("{}", str::from_utf8(out.stderr.as_slice())?);

    Ok(())
}
