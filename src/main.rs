#[macro_use]
extern crate error_chain;
extern crate clap;

use clap::{App, Arg, SubCommand};
use std::fs::File;
use std::io::Read;

error_chain! {
    foreign_links {
        Io(std::io::Error);
    }
}

#[derive(Debug, PartialEq)]
enum EncodingType {
    Simple, AdditionalByte, Stream, Special
}

fn dump(file: &str) -> std::io::Result<()> {
    let f = File::open(file)?;
    let mut count = 0;
    for byte in f.bytes() {
        print!("{:02x}", byte.unwrap());
        count += 1;
        if count % 16 == 0 {
            print!("\n");
        } else {
            print!(" ");
        }
    }
    print!("\n");
    Ok(())
}

fn parse(file: &str) -> std::result::Result<(), std::io::Error> {
    let mut f = File::open(file)?;
    let mut magic_raw = [0u8; 5];
    let mut version_raw = [0u8; 4];
    f.read_exact(&mut magic_raw)?;
    let magic = std::str::from_utf8(&magic_raw).unwrap();
    verify(&magic).unwrap();
    f.read_exact(&mut version_raw)?;
    let version = std::str::from_utf8(&version_raw).unwrap().parse::<u32>().unwrap();
    println!("RDB version is {}", version);
    loop {
        let mut opcode = [0u8; 1];
        f.read_exact(&mut opcode)?;
        f = match opcode[0] {
            0xFA => parse_aux(f),
            _ => break
        };
    }
    
    Ok(())
}

fn parse_aux(mut f: std::fs::File) -> std::fs::File {
    println!("AUX");
    let mut key = String::new();
    let mut value = String::new();
    f = read(f, &mut key);
    f = read(f, &mut value);
    println!("key={} value={}", key, value);
    f
}

fn read(mut f: std::fs::File, result: &mut String) -> std::fs::File {
    let mut size_raw = [0u8; 1];
    f.read_exact(&mut size_raw).unwrap();
    *result = match decide_encoding_type(size_raw[0]).unwrap() {
        EncodingType::Simple => {
            let size = size_raw[0] as usize;
            let mut key = vec![0u8; size];
            f.read_exact(&mut key).unwrap();
            String::from_utf8(key).unwrap()
        },
        EncodingType::Stream => unsafe {
            let mut stream_size = [0u8; 4];
            f.read_exact(&mut stream_size).unwrap();
            std::mem::transmute::<[u8; 4], i32>(stream_size).to_string()
        },
        EncodingType::Special => unsafe {
            match size_raw[0] & 0x3F {
                0 => {
                    let mut b = [0u8; 1];
                    f.read_exact(&mut b).unwrap();
                    b[0].to_string()
                },
                1 => {
                    let mut b = [0u8; 2];
                    f.read_exact(&mut b).unwrap();
                    std::mem::transmute::<[u8; 2], i16>(b).to_string()
                },
                2 => {
                    let mut b = [0u8; 4];
                    f.read_exact(&mut b).unwrap();
                    std::mem::transmute::<[u8; 4], i32>(b).to_string()
                }
                3 => {
                    panic!("It's Compressed String, but not implemented yet")
                }
                _ => panic!("Invalid encoding")
            }
        }
        _ => panic!("Not implemented")
    };
    f
}

fn decide_encoding_type(b: u8) -> std::result::Result<EncodingType, &'static str> {
    match b >> 6 {
        0 => Ok(EncodingType::Simple),
        1 => Ok(EncodingType::AdditionalByte),
        2 => Ok(EncodingType::Stream),
        3 => Ok(EncodingType::Special),
        _ => Err("Invalid encoding")
    }
}

fn verify(magic: &str) -> std::result::Result<(), &'static str> {
    match magic {
        "REDIS" => Ok(()),
        _ => Err("It's not RDB file")
    }
}

fn main() {
    let matches = App::new("RDB dumpper")
        .version("0.1.0")
        .author("Yuta Hongo <yutago@gmail.com>")
        .about("RDB file dumpper")
        .subcommand(
            SubCommand::with_name("dump")
                .about("Show RDB hex dump")
                .arg(
                    Arg::with_name("file")
                        .short("f")
                        .takes_value(true)
                        .help("Specify a target file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("parse")
                .about("Parse RDB file")
                .arg(
                    Arg::with_name("file")
                        .short("f")
                        .takes_value(true)
                        .help("Specify a target file"),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("dump") {
        let file = matches.value_of("file").unwrap_or("dump.rdb");
        match dump(file) {
            Ok(_) => (),
            Err(err) => println!("error {}", err),
        };
    }

    if let Some(matches) = matches.subcommand_matches("parse") {
        let file = matches.value_of("file").unwrap_or("dump.rdb");
        match parse(file) {
            Ok(_) => println!("It's rdb file"),
            Err(err) => println!("error {}", err)
        }
    }
}
