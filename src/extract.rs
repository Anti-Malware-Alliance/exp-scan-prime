use chrono::{TimeZone, Utc};
use lief::pe::headers::Characteristics;
use std::error::Error;

/* DATA DIRECTORY LAYOUT
* 0: Export Table
* 1: Import Table
* 2: Resource Table
* 3: Exception Table
* 4:Certificate Table
* 5: Base_Relocation_Table
* 6: Debug Table
* 7: Architecture
* 8: Gloabl_Ptr
* 9: TLS_Table
* 10: Load_Config_table
* 11: Bound Import
* 12: IAT
* 13: Delay Import Descriptor
* 14: CLR_RUNTIME_HEADER
* 15: Reserved
*/

//return String which is row, and bool saying if file is x64
pub fn extract_csv_row(file_name: &str) -> Result<(String, bool), Box<dyn Error>> {
    let mut file = std::fs::File::open(file_name)?;
    if let Some(lief::Binary::PE(pe_file)) = lief::Binary::from(&mut file) {
        let header = pe_file.header();
        let chars = header.characteristics();
        let mut row: String;
        let is_x64 = !chars.intersects(Characteristics::NEED_32BIT_MACHINE);

        //file name and bit arch
        if is_x64 {
            row = format!("{},64BIT", file_name);
        } else {
            row = format!("{},32BIT", file_name);
        }

        //target machine for compilation
        row = format!("{},{:?}", row, header.machine());

        //number of sections
        row = format!("{},{}", row, header.nb_sections());

        //timestamp
        let datetime = Utc
            .timestamp_millis_opt(header.time_date_stamp() as i64 * 1000)
            .unwrap();
        let datetime_str = format!("{} UTC", datetime.format("%Y-%m-%d %H:%M:%S"));
        row = format!("{},{}", row, datetime_str);

        //size of optional header AND data directories
        //should be 224 for 32bit or 240 for 64bit
        row = format!("{},{}", row, header.sizeof_optional_header());

        //File Characteristics
        let mut char_str = "".to_owned();
        for c in chars.iter_names() {
            if c.0 != "NEED_32BIT_MACHINE" {
                //not relevant, already know if file is 32bit
                if char_str.is_empty() {
                    char_str = c.0.to_owned();
                } else {
                    char_str = format!("{} | {}", char_str, c.0);
                }
            }
        }
        row = format!("{},{}", row, char_str);

        //optional header data
        row = format!(
            "{},{}",
            row,
            extract_opt_header(&pe_file.optional_header(), &is_x64)
        );

        //imports
        let imports = pe_file.imports();
        let delay_imports = pe_file.delay_imports();
        let mut import_str = "".to_owned();
        for i in imports {
            if import_str.is_empty() {
                import_str = i.name();
            } else {
                import_str = format!("{} | {}", import_str, i.name());
            }
        }
        for d in delay_imports {
            if import_str.is_empty() {
                import_str = d.name();
            } else {
                import_str = format!("{} | {}", import_str, d.name());
            }
        }
        row = format!("{},{}", row, import_str);

        //Signature Certification
        let signatures = pe_file.signatures();
        if signatures.len() == 0 {
            row = format!("{},NO SIGNATURE DETECTED", row);
        } else {
            let mut sig_str = "".to_owned();
            for s in signatures {
                let signs = s.signers();
                for c in signs {
                    if sig_str.is_empty() {
                        sig_str = c.issuer().replace(",", "|");
                    } else {
                        sig_str = format!("{} \\/ {}", sig_str, c.issuer().replace(",", "|"));
                    }
                }
            }
            row = format!("{},{}", row, sig_str);
        }

        Ok((row, is_x64))
    } else {
        //empty row signifies not PE file
        //TODO: Figure out a better way to do this. Crate to derive error trait?
        println!("{} IS NOT NOT PE FORMAT", file_name);
        Ok(("".to_owned(), false))
    }
}

fn extract_opt_header(opt_header: &lief::pe::OptionalHeader, is_x64: &bool) -> String {
    let mut row: String;
    //Linker Version
    row = format!(
        "{}.{}",
        opt_header.major_linker_version(),
        opt_header.minor_linker_version()
    );

    //Size of code, initialized data, uninitialized data
    row = format!(
        "{},{},{},{}",
        row,
        opt_header.sizeof_code(),
        opt_header.sizeof_initialized_data(),
        opt_header.sizeof_uninitialized_data()
    );

    //address of entry point
    row = format!("{},{:#X}", row, opt_header.addressof_entrypoint());

    //base of code
    row = format!("{},{:#X}", row, opt_header.baseof_code());

    //base of data
    if !is_x64 {
        row = format!("{},{:#X}", row, opt_header.baseof_data());
    }

    //image base
    row = format!("{},{:#X}", row, opt_header.imagebase());

    //section and file alignment
    row = format!(
        "{},{},{}",
        row,
        opt_header.section_alignment(),
        opt_header.file_alignment()
    );

    //OS, image, and subsystem version
    row = format!(
        "{},{}.{},{}.{},{}.{}",
        row,
        opt_header.major_operating_system_version(),
        opt_header.minor_operating_system_version(),
        opt_header.major_image_version(),
        opt_header.minor_image_version(),
        opt_header.major_subsystem_version(),
        opt_header.minor_subsystem_version()
    );

    //size of image and headers
    row = format!(
        "{},{},{}",
        row,
        opt_header.sizeof_image(),
        opt_header.sizeof_headers()
    );

    //subsystem
    row = format!("{},{:?}", row, opt_header.subsystem());

    //dll characteristics
    let dll_char = opt_header.dll_characteristics();
    let mut dll_str = "".to_owned();
    for d in dll_char.iter_names() {
        if dll_str.is_empty() {
            dll_str = d.0.to_owned();
        } else {
            dll_str = format!("{} | {}", dll_str, d.0);
        }
    }

    row = format!("{},{}", row, dll_str.to_uppercase());

    //stack and heap sizes
    row = format!(
        "{},{},{},{},{}",
        row,
        opt_header.sizeof_stack_reserve(),
        opt_header.sizeof_stack_commit(),
        opt_header.sizeof_heap_reserve(),
        opt_header.sizeof_heap_commit()
    );

    //number of rva and size
    row = format!("{},{}", row, opt_header.numberof_rva_and_size());

    row
}
