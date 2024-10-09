use exe::pe::VecPE;
use exe::types::CCharString;
use exe::types::ImportDirectory;
use std::error::Error;

pub fn get_import_names(image: &VecPE) -> Result<String, Box<dyn Error>> {
    let imports = ImportDirectory::parse(image)?.descriptors;
    let mut ret_str = String::new();
    for dir in imports {
        let name = dir.get_name(image)?;
        ret_str = format!("{} | {}", ret_str, name.as_str()?);
    }
    Ok(ret_str)
}
