use pe_parser::{
    coff::CoffFileHeader,
    optional::{Optional, OptionalHeader64},
    pe::{parse_portable_executable, PortableExecutable},
};
use std::{error::Error, fs::{self, File}, io::Write, env, process::Command, str };

fn parse_pe_data(pe: &PortableExecutable) -> Result<String, Box<dyn Error>> {
    let coff_dat = parse_coff_data(&pe.coff)?;
    let opt_dat = parse_opt_header_data_64(&pe.optional_header_64.unwrap())?;
    Ok(format!("{},{}\n", coff_dat, opt_dat))
}

fn get_coff_headers() -> String{
    //format! is unnecessary, but easier to read
    format!("{},{},{},{},{},{},{}",
        "machine_type",
        "number_of_sections",
        "timestamp",
        "symbol_table_pointer",
        "number_of_symbols",
        "option_header_size",
        "characteristics"
    )
}

fn parse_coff_data(coff: &CoffFileHeader) -> Result<String, Box<dyn Error>> {
    let coff_data = format!(
        "{:?},{},{},{:#010x},{},{},{}",
        coff.get_machine_type().expect("Failed to get machine type"),
        coff.number_of_sections,
        coff.get_time_date_stamp().expect("Failt to get timestamp"),
        coff.pointer_to_symbol_table,
        coff.number_of_symbols,
        coff.size_of_optional_header,
        coff.get_characteristics().expect("Failed to get characteristics"),
    );

    Ok(coff_data)
}

fn get_opt_header_headers() -> String{
    format!("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        "magic_number",
        "linker_version",
        "size_of_code",
        "size_of_initialized_data",
        "size_of_uninitialized_data",
        "entry_point_address",
        "base_of_code",
        "image_base",
        "section_alignment",
        "file_alignment",
        "os_version",
        "image_version",
        "subsystem_version",
        "win32_version_value",
        "size_of_image",
        "size_of_headers",
        "checksum",
        "subsystem",
        "dll_characteristics",
        "size_of_stack_reserve",
        "size_of_stack_commit",
        "size_of_heap_reserve",
        "size_of_heap_commit",
        "loader_flags",
        "number_of_rva_and_sizes"
    )

}

fn parse_opt_header_data_64(opt: &OptionalHeader64) -> Result<String, Box<dyn Error>> {
    let opt_data = format!(
        "{},{}.{},{},{},{},{:#010x},{:#010x},{:#010x},{},{},{}.{},{}.{},{}.{},{},{},{},{},{:?},{},{},{},{},{},{},{}",
        "PE32+", 
        opt.major_linker_version, 
        opt.minor_linker_version,
        opt.size_of_code,
        opt.size_of_initialized_data,
        opt.size_of_uninitialized_data,
        opt.address_of_entry_point,
        opt.base_of_code,
        opt.image_base,
        opt.section_alignment,
        opt.file_alignment,
        opt.major_operating_system_version,
        opt.minor_operating_system_version,
        opt.major_image_version,
        opt.minor_image_version,
        opt.major_subsystem_version,
        opt.minor_subsystem_version,
        opt.win32_version_value,
        opt.size_of_image,
        opt.size_of_headers,
        opt.check_sum,
        opt.get_subsystem().expect("Failed to get subsystem"),
        opt.get_dll_characteristics().expect("Failed to get DLL characteristics"),
        opt.size_of_stack_reserve,
        opt.size_of_stack_commit,
        opt.size_of_heap_reserve,
        opt.size_of_heap_commit,
        opt.loader_flags,
        opt.number_of_rva_and_sizes
    );

    Ok(opt_data)
}

#[derive(Debug)]
enum ValidArgs{
    InvalidArgNum,
    InvalidFileName
}

fn validate_args() -> Result<String, ValidArgs>{
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2{
        return Err(ValidArgs::InvalidArgNum)
    }
    if fs::metadata(args[1].as_str()).is_err(){
        return Err(ValidArgs::InvalidFileName)
    }

    Ok(args[1].clone())
}

fn main() -> Result<(), Box<dyn Error>> {


    let file_name = validate_args().unwrap();

    let file = fs::read(file_name.as_str())?;
    let pe = parse_portable_executable(file.as_slice())?;
    let csv_headers = format!("{},{}\n", get_coff_headers(), get_opt_header_headers());
    let csv_data = parse_pe_data(&pe)?;

    { // controllin the scope of the file to make sure it closed before the script is called
        let mut f = File::create("result/sample.csv").expect("Unable to create file");
        f.write_all(format!("{}{}", csv_headers, csv_data).as_bytes()).expect("Unable to write data");
   }  
    

    let out = Command::new("python3")
        .args(["scripts/csv_to_parquet.py", "result/sample.csv"])
        .output()
        .expect("Failed to convert csv to parquet. Make sure `python3` is on your PATH");
    
    println!("{}",str::from_utf8(out.stdout.as_slice())?);
    println!("{}",str::from_utf8(out.stderr.as_slice())?);

    Ok(())
}
