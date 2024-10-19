use chrono::Local;
use exe::pe::{VecPE, PE};
use rayon::prelude::*;
use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::Write,
    process::Command,
    str,
    sync::Mutex,
};
mod pe_collector;
mod pe_imports;

#[derive(Debug)]
enum ArgError {
    InvalidArgNum,
    InvalidFileName,
}

fn is_valid_arg(args: &[String]) -> Result<(), ArgError> {
    if args.len() == 1 {
        return Err(ArgError::InvalidArgNum);
    }
    let mut arg_iter = args.iter();

    arg_iter.next(); //skipping the cwd

    for arg in arg_iter {
        if fs::metadata(arg).is_err() {
            eprintln!("INVALID FILE/DIRECTORY NAME: {}", arg);
            return Err(ArgError::InvalidFileName);
        }
    }

    Ok(())
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

fn convert_csv(file_name: &str) -> Result<(), Box<dyn Error>> {
    let _ = Command::new("python3")
        .args(["scripts/csv_to_parquet.py", file_name])
        .output()
        .expect("Failed to convert csv to parquet. Make sure `python3` is on your PATH");

    // println!("{}", str::from_utf8(out.stdout.as_slice())?);
    // println!("{}", str::from_utf8(out.stderr.as_slice())?);

    Ok(())
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

fn build_csv_rows(file_names: &[String]) -> Result<(Vec<String>, Vec<String>), Box<dyn Error>> {
    let csv_vec_64 = Mutex::new(vec![]);
    let csv_vec_32 = Mutex::new(vec![]);

    file_names.par_iter().for_each(|file| {
        let poss_image = VecPE::from_disk_file(file);

        match poss_image {
            Ok(image) => {
                let is_x64 = image.get_arch().unwrap() == exe::Arch::X64;

                if is_x64 {
                    let mut v = csv_vec_64.lock().unwrap();
                    v.push(format!(
                        "{},{}",
                        file,
                        pe_collector::parse_64(&image).unwrap()
                    ));
                } else {
                    let mut v = csv_vec_32.lock().unwrap();
                    v.push(format!(
                        "{},{}",
                        file,
                        pe_collector::parse_32(&image).unwrap()
                    ));
                }
            }
            Err(_) => eprintln!("Error parsing {}, skipping...", file),
        }
    });
    let x64_csv = csv_vec_64.lock().unwrap().clone();
    let x32_csv = csv_vec_32.lock().unwrap().clone();
    Ok((x64_csv, x32_csv))
}

fn append_or_create_csv(
    file_name: &str,
    data: &Vec<String>,
    header: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    if fs::metadata(file_name).is_err() {
        // if file does not exist
        let mut f =
            File::create(file_name).expect(format!("Unable to create file {}", file_name).as_str());
        f.write_all(header.unwrap().as_bytes())
            .expect("Unable to write header");
        f.write_all("\n".as_bytes())
            .expect("Unable to wirte newline after header");
        for dat in data {
            f.write_all(dat.as_bytes()).expect("Unable to write Data");
            f.write_all("\n".as_bytes())
                .expect("Unable to write new line");
        }
    } else {
        let mut f = OpenOptions::new()
            .append(true)
            .open(file_name)
            .expect("Unable to write to file");
        let mut perms = fs::metadata(file_name)?.permissions();
        perms.set_readonly(false);
        fs::set_permissions(file_name, perms)?;
        for dat in data {
            f.write_all(dat.as_bytes()).expect("Unable to append Data");
            f.write_all("\n".as_bytes())
                .expect("unable to append new line");
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let _date_time = Local::now();
    let args: Vec<String> = env::args().collect();
    match is_valid_arg(&args) {
        Ok(_) => (),
        Err(s) => {
            println!("ERROR: {:?}", s);
            return Ok(());
        }
    }

    // let csv_file_name = format!("{}", date_time.format("%Y_%m_%d-%H:%M:%S"));
    // let csv_64_bit = format!("result/{}_x64.csv", csv_file_name);
    // let csv_32_bit = format!("result/{}_x32.csv", csv_file_name);

    //to_owend isn't necessary, just to keep it in line iwth the timestamp file names
    let csv_64_bit = "result/sample64.csv".to_owned();
    let csv_32_bit = "result/sample32.csv".to_owned();

    let files = collect_file_paths(&args[1..])?;
    let (csv64, csv32) = build_csv_rows(&files)?;
    append_or_create_csv(
        csv_64_bit.as_str(),
        &csv64,
        Some(pe_collector::get_csv_headers_64().as_str()),
    )?;
    append_or_create_csv(
        csv_32_bit.as_str(),
        &csv32,
        Some(pe_collector::get_csv_headers_32().as_str()),
    )?;

    convert_csv(csv_64_bit.as_str())?;
    convert_csv(csv_32_bit.as_str())?;

    Ok(())
}
