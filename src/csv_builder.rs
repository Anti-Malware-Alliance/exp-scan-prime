use crate::extract;
use rayon::prelude::*;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    sync::Mutex,
};

pub fn extract_to_csv(files: &[String]) -> (String, String) {
    let csv_x64_name = "result/sample64.csv";
    let csv_x32_name = "result/sample32.csv";

    let (x64_rows, x32_rows) = build_csv_rows(files);

    if fs::metadata(csv_x64_name).is_err() {
        //does file exist
        create_csv(csv_x64_name, &x64_rows, get_x64_headers().as_str());
    } else {
        append_csv(csv_x64_name, &x64_rows);
    }

    if fs::metadata(csv_x32_name).is_err() {
        //does file exist
        create_csv(csv_x32_name, &x32_rows, get_x32_headers().as_str());
    } else {
        append_csv(csv_x32_name, &x32_rows);
    }

    (csv_x32_name.to_owned(), csv_x64_name.to_owned())
}

pub fn get_x64_headers() -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        "file_name",
        "bit_architecture",
        "machine_type",
        "number_of_sections",
        "timestamp",
        "size_of_optional_header",
        "file_characteristics",
        "linker_version",
        "size_of_code",
        "size_of_initialized_data",
        "size_of_uninitialized_data",
        "address_of_entry_point",
        "base_of_code",
        "image_base",
        "section_alignment",
        "file_alignment",
        "OS_version",
        "image_version",
        "subsystem_version",
        "size_of_image",
        "size_of_headers",
        "subsystem",
        "dll_characteristics",
        "size_of_stack_reserve",
        "size_of_stack_commit",
        "size_of_heap_reserve",
        "size_of_heap_commit",
        "number_of_rva_and_sizes",
        "import_directory",
        "signature_signers"
    )
}

pub fn get_x32_headers() -> String {
    get_x64_headers().replace(
        "base_of_code,image_base",
        "base_of_code,base_of_data,image_base",
    )
}

fn create_csv(file_name: &str, data: &[String], header: &str) {
    let mut f = File::create(file_name).expect("Unable to create file");
    f.write_all(header.as_bytes())
        .expect("Unable to write header");
    f.write_all("\n".as_bytes())
        .expect("Unable to write new line");
    for dat in data {
        f.write_all(dat.as_bytes()).expect("Unable to write data");
        f.write_all("\n".as_bytes())
            .expect("Unable to write new line");
    }
}

fn append_csv(file_name: &str, data: &[String]) {
    let mut f = OpenOptions::new()
        .append(true)
        .open(file_name)
        .expect("Unable to append to file");
    let mut perms = fs::metadata(file_name).unwrap().permissions();
    perms.set_readonly(false);
    fs::set_permissions(file_name, perms).unwrap(); // ensure we can write to the existing file
    for dat in data {
        f.write_all(dat.as_bytes()).expect("Unable to append Data");
        f.write_all("\n".as_bytes())
            .expect("Unable to append new line");
    }
}

pub fn build_csv_rows(file_names: &[String]) -> (Vec<String>, Vec<String>) {
    let csv_vec_64 = Mutex::new(vec![]);
    let csv_vec_32 = Mutex::new(vec![]);

    file_names.par_iter().for_each(|file| {
        if let Ok((row, is_x64)) = extract::extract_csv_row(file) {
            if is_x64 {
                let mut v = csv_vec_64.lock().unwrap();
                v.push(row);
            } else {
                let mut v = csv_vec_32.lock().unwrap();
                v.push(row);
            }
        } else {
            eprintln!("Error parsing {}, skipping...", file);
        }
    });
    let x64_csv = csv_vec_64.lock().unwrap().clone();
    let x32_csv = csv_vec_32.lock().unwrap().clone();
    (x64_csv, x32_csv)
}
