use chrono::{TimeZone, Utc};
use exe::headers::FileCharacteristics;
use exe::pe::{VecPE, PE};
use exe::DLLCharacteristics;
use num_derive::FromPrimitive;
use std::error::Error;

// TODO: look into changing these into enums
const FILE_CHARS: [&str; 16] = [
    "RELOCS_STRIPPED",
    "EXECUTABLE_IMAGE",
    "LINE_NUMS_STRIPPED_DEPRECATED",
    "LOCAL_SYMS_STRiPPED_DEPRECATED",
    "AGGRESSIVE_WS_TRIM_DEPRECATED",
    "LARGE_ADDRESS_AWARE",
    "RESERVED",
    "BYTES_RESERVED_LO_DEPRECATED",
    "32BIT_MACHINE",
    "DEBUG_STRIPPED",
    "REMOVABLE_RUN_FROM_SWAP",
    "NET_RUN_FROM_SWAP",
    "SYSTEM",
    "DLL",
    "UP_SYSTEM_ONLY",
    "BYTES_REVERSE_HI_DEPRECATED",
];

const DLL_CHARS: [&str; 11] = [
    "HIGH_ENTROPY_VA",
    "DYNAMIC_BASE",
    "FORCE_INTEGRITY",
    "NX_COMPAT",
    "NO_ISOLATION",
    "NO_SEH",
    "NO_BIND",
    "APPCONTAINER",
    "WDM_DRIVER",
    "GUARD_CF",
    "TERMINAL_SERVER_AWARE",
];

const SUBSYSTEMS: [&str; 16] = [
    "UNKNOWN",
    "NATIVE",
    "WINDOWS_GUI",
    "WINDOWS_CLI",
    "INVALID",
    "OS2_CLI",
    "POSIX_CLI",
    "NATIVE_WINDOWS",
    "WINDOWS_CE_GUI",
    "EFI_APPLICATION",
    "EFI_BOOT_SERVICE_DRIVER",
    "EFI_RUNTIME_DRIVER",
    "EFI_ROM",
    "XBOX",
    "INVALID",
    "WINDOWS_BOOT_APPLICATION",
];

#[derive(Debug, FromPrimitive)]
pub enum MachineTypes {
    /// The content of this field is assumed to be applicable to any machine type
    Unknown = 0x0,
    /// Alpha AXP, 32-bit address space
    Alpha = 0x184,
    /// Alpha 64/AXP 64, 64-bit address space
    Alpha64 = 0x284,
    /// Matsushita AM33
    AM33 = 0x1d3,
    /// x64
    AMD64 = 0x8664,
    /// ARM little endian
    ARM = 0x1c0,
    /// ARM64 little endian
    ARM64 = 0xaa64,
    /// ARM Thumb-2 little endian
    ARMNT = 0x1c4,
    /// EFI byte code
    EBC = 0xebc,
    /// Intel 386 or later processors and compatible processors
    I386 = 0x14c,
    /// Intel Itanium processor family
    IA64 = 0x200,
    /// LoongArch 32-bit processor family
    LoongArch32 = 0x6232,
    /// LoongArch 64-bit processor family
    LoongArch64 = 0x6264,
    /// Mitsubishi M32R little endian
    M32R = 0x9041,
    /// MIPS16
    MIPS16 = 0x266,
    /// MIPS with FPU
    MIPSFPU = 0x366,
    /// MIPS16 with FPU
    MIPSFPU16 = 0x466,
    /// Power PC little endian
    PowerPC = 0x1f0,
    /// Power PC with floating point support
    PowerPCFP = 0x1f1,
    /// MIPS little endian
    R4000 = 0x166,
    /// RISC-V 32-bit address space
    RISCV32 = 0x5032,
    /// RISC-V 64-bit address space
    RISCV64 = 0x5064,
    /// RISC-V 128-bit address space
    RISCV128 = 0x5128,
    /// Hitachi SH3
    SH3 = 0x1a2,
    /// Hitachi SH3 DSP
    SH3DSP = 0x1a3,
    /// Hitachi SH4
    SH4 = 0x1a6,
    /// Hitachi SH5
    SH5 = 0x1a8,
    /// Thumb
    Thumb = 0x1c2,
    /// MIPS little-endian WCE v2
    WCEMIPSV2 = 0x169,
}

pub fn parse_64(image: &VecPE) -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{},{}",
        collect_coff_str_64(image)?,
        collect_optional_head_str_64(image)?
    ))
}

pub fn get_csv_headers_64() -> String {
    let head = format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        "file_name",
        "architecture",
        "machine_type",
        "number_of_sections",
        "timestamp",
        "table_pointer",
        "number_of_symbols",
        "size_of_optional_header",
        "file_characteristics",
        "magic_number",
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
        "checksum_validation",
        "subsystem",
        "dll_characteristics",
        "size_of_stack_reserve",
        "size_of_stack_commit",
        "size_of_heap_reserve",
        "size_of_heap_commit",
        "loader_flags",
        "number_of_rva_and_sizes"
    );

    return head;
}

//this collect the informaiton in the COFF header to human readable format
fn collect_coff_str_64(image: &VecPE) -> Result<String, Box<dyn Error>> {
    let header = image.get_valid_nt_headers_64()?.file_header;

    let machine_type: MachineTypes = match num::FromPrimitive::from_u16(header.machine) {
        Some(s) => s,
        None => MachineTypes::Unknown,
    };
    let machine_type_str = format!("{:?}", machine_type);

    let datetime = Utc
        .timestamp_millis_opt((header.time_date_stamp as i64) * 1000)
        .unwrap();
    let datetime_str = format!("{} UTC", datetime.format("%Y-%m-%d %H:%M:%S").to_string());
    let exe::Offset(table_pointer) = header.pointer_to_symbol_table;
    let table_pointer_str = format!("{:#X}", table_pointer);

    let file_char_str = get_file_chracteristics(&header.characteristics).join(" | ");

    let coff_str = format!(
        "64BIT,{},{},{},{},{},{},{}",
        machine_type_str,
        header.number_of_sections,
        datetime_str,
        table_pointer_str,
        header.number_of_symbols,
        header.size_of_optional_header,
        file_char_str
    );
    Ok(coff_str)
}

fn collect_optional_head_str_64(image: &VecPE) -> Result<String, Box<dyn Error>> {
    let header = image.get_valid_nt_headers_64()?.optional_header;
    let magic_str = match header.magic {
        0x10b => "PE32",
        0x20b => "PE32+",
        _ => "INVALID MAGIC NUMBER",
    }
    .to_owned();

    let linker_ver_str = format!(
        "{}.{}",
        header.major_linker_version, header.minor_linker_version
    );

    let image_ver_str = format!(
        "{}.{}",
        header.major_image_version, header.minor_image_version
    );

    let os_ver_str = format!(
        "{}.{}",
        header.major_operating_system_version, header.minor_operating_system_version
    );

    let subsystem_ver_str = format!(
        "{}.{}",
        header.major_subsystem_version, header.minor_operating_system_version
    );

    let dll_str = get_dll_characteristics(&header.dll_characteristics).join(" | ");

    let subsystem_type_str = SUBSYSTEMS[header.subsystem as usize].to_owned();

    let checksum_str = if image.validate_checksum()? {
        "VALID_CHECKSUM".to_owned()
    } else {
        "INVALID_CHECKSUM".to_owned()
    };

    let opt_head = format!(
        "{},{},{},{},{},{:#X},{:#X},{:#X},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        magic_str,
        linker_ver_str,
        header.size_of_code,
        header.size_of_initialized_data,
        header.size_of_uninitialized_data,
        header.address_of_entry_point.0,
        header.base_of_code.0,
        header.image_base,
        header.section_alignment,
        header.file_alignment,
        os_ver_str,
        image_ver_str,
        subsystem_ver_str,
        header.size_of_image,
        header.size_of_headers,
        checksum_str,
        subsystem_type_str,
        dll_str,
        header.size_of_stack_reserve,
        header.size_of_stack_commit,
        header.size_of_heap_reserve,
        header.size_of_heap_commit,
        header.loader_flags,
        header.number_of_rva_and_sizes
    );

    return Ok(opt_head);
}

pub fn parse_32(image: &VecPE) -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{},{}",
        collect_coff_str_32(image)?,
        collect_optional_head_str_32(image)?
    ))
}
pub fn get_csv_headers_32() -> String {
    let head = format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        "file_name",
        "architecture",
        "machine_type",
        "number_of_sections",
        "timestamp",
        "table_pointer",
        "number_of_symbols",
        "size_of_optional_header",
        "file_characteristics",
        "magic_number",
        "linker_version",
        "size_of_code",
        "size_of_data",
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
        "checksum_validation",
        "subsystem",
        "dll_characteristics",
        "size_of_stack_reserve",
        "size_of_stack_commit",
        "size_of_heap_reserve",
        "size_of_heap_commit",
        "loader_flags",
        "number_of_rva_and_sizes"
    );

    return head;
}

fn collect_coff_str_32(image: &VecPE) -> Result<String, Box<dyn Error>> {
    let header = image.get_valid_nt_headers_32()?.file_header;

    let machine_type: MachineTypes = match num::FromPrimitive::from_u16(header.machine) {
        Some(s) => s,
        None => MachineTypes::Unknown,
    };
    let machine_type_str = format!("{:?}", machine_type);

    let datetime = Utc
        .timestamp_millis_opt((header.time_date_stamp as i64) * 1000)
        .unwrap();
    let datetime_str = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    let exe::Offset(table_pointer) = header.pointer_to_symbol_table;
    let table_pointer_str = format!("{:#X}", table_pointer);

    let file_char_str = get_file_chracteristics(&header.characteristics).join(" | ");

    let coff_str = format!(
        "32BIT,{},{},{},{},{},{},{}",
        machine_type_str,
        header.number_of_sections,
        datetime_str,
        table_pointer_str,
        header.number_of_symbols,
        header.size_of_optional_header,
        file_char_str
    );
    Ok(coff_str)
}
fn collect_optional_head_str_32(image: &VecPE) -> Result<String, Box<dyn Error>> {
    let header = image.get_valid_nt_headers_32()?.optional_header;
    let magic_str = match header.magic {
        0x10b => "PE32",
        0x20b => "PE32+",
        _ => "INVALID MAGIC NUMBER",
    }
    .to_owned();

    let linker_ver_str = format!(
        "{}.{}",
        header.major_linker_version, header.minor_linker_version
    );

    let image_ver_str = format!(
        "{}.{}",
        header.major_image_version, header.minor_image_version
    );

    let os_ver_str = format!(
        "{}.{}",
        header.major_operating_system_version, header.minor_operating_system_version
    );

    let subsystem_ver_str = format!(
        "{}.{}",
        header.major_subsystem_version, header.minor_operating_system_version
    );

    let dll_str = get_dll_characteristics(&header.dll_characteristics).join(" | ");

    let subsystem_type_str = SUBSYSTEMS[header.subsystem as usize].to_owned();

    let checksum_str = if image.validate_checksum()? {
        "VALID_CHECKSUM".to_owned()
    } else {
        "INVALID_CHECKSUM".to_owned()
    };

    let opt_head = format!(
        "{},{},{},{},{},{:#X},{:#X},{:#X},{:#X},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        magic_str,
        linker_ver_str,
        header.size_of_code,
        header.size_of_initialized_data,
        header.size_of_uninitialized_data,
        header.address_of_entry_point.0,
        header.base_of_code.0,
        header.base_of_data.0,
        header.image_base,
        header.section_alignment,
        header.file_alignment,
        os_ver_str,
        image_ver_str,
        subsystem_ver_str,
        header.size_of_image,
        header.size_of_headers,
        checksum_str,
        subsystem_type_str,
        dll_str,
        header.size_of_stack_reserve,
        header.size_of_stack_commit,
        header.size_of_heap_reserve,
        header.size_of_heap_commit,
        header.loader_flags,
        header.number_of_rva_and_sizes
    );

    return Ok(opt_head);
}

fn get_file_chracteristics(file_chars: &FileCharacteristics) -> Vec<String> {
    let mut curr_bit_flag = 0x0001;

    let mut characteristics: Vec<String> = Vec::new();

    for s in FILE_CHARS.iter() {
        if curr_bit_flag & file_chars.bits() == curr_bit_flag {
            characteristics.push(s.to_owned().to_owned());
        }
        curr_bit_flag <<= 1; // shifts 1 bit to the left.
    }
    return characteristics;
}

fn get_dll_characteristics(dll_chars: &DLLCharacteristics) -> Vec<String> {
    let mut curr_bit_flag = 0x0020;
    let mut characteristics: Vec<String> = Vec::new();

    for s in DLL_CHARS.iter() {
        if curr_bit_flag & dll_chars.bits() == curr_bit_flag {
            characteristics.push(s.to_owned().to_owned());
        }
        curr_bit_flag <<= 1; // shifts 1 bit to the left
    }

    return characteristics;
}
