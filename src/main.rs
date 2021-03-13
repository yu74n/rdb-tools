#[macro_use]
extern crate error_chain;
extern crate clap;

use clap::{App, Arg, SubCommand};
use core::panic;
use std::{fs::File, usize};
use std::io::{Read, BufReader};
use byteorder::{LittleEndian,BigEndian,ReadBytesExt};
use lzf;

error_chain! {
    foreign_links {
        Io(std::io::Error);
    }
}

#[derive(Debug, PartialEq)]
enum EncodingType {
    Simple,
    AdditionalByte,
    Stream,
    Special
}

#[derive(Debug)]
enum ValueType {
    String,
    List,
    Set,
    SortedSet,
    Hash,
    Skiplist,
    Zipmap,
    Ziplist,
    Intset,
    SortedSetInZiplist,
    HashmapInZiplist,
    Quicklist
}

pub struct Parser<R: Read> {
    input: R
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

fn dump_buf(buf: &Vec<u8>) {
    let mut count = 0;
    for byte in buf {
        print!("{:02x}", byte);
        count += 1;
        if count % 16 == 0 {
            print!("\n");
        } else {
            print!(" ");
        }
    }
    print!("\n");
}

impl<R: Read> Parser<R>{
    pub fn new(input: R) -> Parser<R> {
        Parser{
            input: input
        }
    }

    pub fn parse(&mut self) -> std::result::Result<(), std::io::Error> {
        verify_magic(&mut self.input).unwrap();
        verify_version(&mut self.input);
        loop {
            let opcode = self.input.read_u8()?;
            match opcode {
                0xFA => {
                    let key = read_string(&mut self.input);
                    let value = read_string(&mut self.input);
                    println!("{}:{}", key, value);
                }
                0xFB => {
                    let hash_table_size = decode_length(&mut self.input);
                    let expiry_hash_table_size = decode_length(&mut self.input);
                    println!("hash_table_size={}, expiry_table_size={}", hash_table_size, expiry_hash_table_size);
                }
                0xFE => {
                    parse_db(&mut self.input);
                }
                0xFF => break,
                _ => {
                    let value_type = decode_value_type(opcode);
                    let key = read_string(&mut self.input);
                    println!("type={:?}, key={}", value_type, key);
                    decode_value(&mut self.input, &value_type);
                }
            };
        }
        
        Ok(())
    }
}

fn verify_magic(reader: &mut dyn Read) -> std::result::Result<(), &'static str> {
    let mut magic_raw = [0u8; 5];
    reader.read_exact(&mut magic_raw).unwrap();
    let magic = std::str::from_utf8(&magic_raw).unwrap();
    match magic {
        "REDIS" => Ok(()),
        _ => Err("It's not RDB file")
    }
}

fn verify_version(reader: &mut dyn Read) {
    let mut version_raw = [0u8; 4];
    
    reader.read_exact(&mut version_raw).unwrap();
    let version = std::str::from_utf8(&version_raw).unwrap().parse::<u32>().unwrap();
    println!("RDB version is {}", version);
}

fn read_string(reader: &mut dyn Read) -> String {
    let len_type = reader.read_u8().unwrap();
    match decide_encoding_type(len_type).unwrap() {
        EncodingType::Simple => {
            let mut buf = vec![0u8; len_type as usize];
            reader.read_exact(&mut buf).unwrap();
            String::from_utf8(buf).unwrap()
        },
        EncodingType::AdditionalByte => {
            let upper = (len_type & 0x3F) as usize;
            let lower = reader.read_u8().unwrap() as usize;
            let len = (upper << 8) + lower;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).unwrap();
            String::from_utf8(buf).unwrap()
        },
        EncodingType::Stream => {
            let len = reader.read_u32::<LittleEndian>().unwrap() as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).unwrap();
            String::from_utf8(buf).unwrap()
        },
        EncodingType::Special => {
            match len_type & 0x3F {
                0 => {
                    reader.read_u8().unwrap().to_string()
                }
                1 => {
                    reader.read_u16::<LittleEndian>().unwrap().to_string()
                }
                2 => {
                    reader.read_u32::<LittleEndian>().unwrap().to_string()
                }
                3 => {
                    let compressed_len = decode_length(reader);
                    let uncompressed_len = decode_length(reader);
                    let mut compressed = vec![0u8; compressed_len];
                    reader.read_exact(&mut compressed).unwrap();
                    let uncompressed = lzf::decompress(&compressed, uncompressed_len).unwrap();
                    String::from_utf8(uncompressed).unwrap()
                }
                _ => panic!("Invalid encoding")
            }
        }
    }
}

fn parse_db(reader: &mut dyn Read) {
    let db_num = decode_length(reader);
    println!("db: {}", db_num);
}

fn decode_value_type(byte: u8) -> ValueType {
    match byte {
        0 => ValueType::String,
        1 => ValueType::List,
        2 => ValueType::Set,
        3 => ValueType::SortedSet,
        4 => ValueType::Hash,
        5 => ValueType::Skiplist,
        9 => ValueType::Zipmap,
        10 => ValueType::Ziplist,
        11 => ValueType::Intset,
        12 => ValueType::SortedSetInZiplist,
        13 => ValueType::HashmapInZiplist,
        14 => ValueType::Quicklist,
        _ => panic!("Unknown ValueType: {:?}", byte)
    }
}

fn decode_value(reader: &mut dyn Read, value_type: &ValueType) {
    match value_type {
        ValueType::String => {
            println!("{}", read_string(reader));
        }
        ValueType::List | ValueType::Set => {
            let size = decode_length(reader);
            println!("len={}", size);
            for _ in 0..size {
                let elem = read_string(reader);
                println!("{}", elem);
            }
        }
        ValueType::Hash => {
            let size = decode_length(reader);
            for _ in 0..size {
                let field = read_string(reader);
                let value = read_string(reader);
                println!("field={}, value={}", field, value);
            }
        }
        ValueType::Skiplist => {
            let size = decode_length(reader);
            for _ in 0..size {
                let member = read_string(reader);
                let score = reader.read_f64::<LittleEndian>().unwrap();
                println!("member={}, score={}", member, score);
            }
        }
        ValueType::SortedSetInZiplist |
        ValueType::HashmapInZiplist => {
            decode_length(reader);
            let entries = decode_ziplist(reader);
            for i in 0..entries.len() / 2 {
                println!("field={}, value={}", entries[i*2], entries[i*2+1])
            }
        }
        _ => panic!("{:?} is not supported yet", value_type)
    }
}

fn decode_length(reader: &mut dyn Read) -> usize {
    let len_type = reader.read_u8().unwrap();
    match decide_encoding_type(len_type).unwrap() {
        EncodingType::Simple => {
            len_type as usize
        },
        EncodingType::AdditionalByte => {
            let upper = (len_type & 0x3F) as usize;
            let lower = reader.read_u8().unwrap() as usize;
            (upper << 8) + lower
        },
        EncodingType::Stream => {
            reader.read_u32::<LittleEndian>().unwrap() as usize
        },
        EncodingType::Special => {
            match len_type & 0x3F {
                0 => {
                    reader.read_u8().unwrap().to_string().parse::<u8>().unwrap() as usize
                }
                1 => {
                    reader.read_u16::<LittleEndian>().unwrap().to_string().parse::<u16>().unwrap() as usize
                }
                2 => {
                    reader.read_u32::<LittleEndian>().unwrap().to_string().parse::<u32>().unwrap() as usize
                }
                3 => {
                    panic!("It's Compressed String, but not implemented yet")
                }
                _ => panic!("Invalid encoding")
            }
        }
    }
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

fn decode_ziplist(buf: &mut dyn Read) -> Vec<String> {
    let size = buf.read_u32::<LittleEndian>().unwrap();
    let offset_to_tail = buf.read_u32::<LittleEndian>().unwrap();
    let entry_len = buf.read_u16::<LittleEndian>().unwrap() as usize;
    println!("ziplist header; size={}, offset_to_tail={}, # of entry={}", size, offset_to_tail, entry_len);
    let mut entries = vec!["".to_string(); entry_len];
    for i in 0..entry_len {
        entries[i] = decode_ziplist_entry(buf);
    }
    let last_byte = buf.read_u8().unwrap();
    assert!(last_byte == 0xFF);
    entries
}

fn decode_ziplist_entry(buf: &mut dyn Read) -> String {
    decode_prev_len(buf);
    read_ziplist_entry_value(buf)
}

fn decode_prev_len(buf: &mut dyn Read) -> usize {
    let first_byte = buf.read_u8().unwrap();
    match first_byte {
        0xFE => {
            buf.read_u32::<BigEndian>().unwrap() as usize
        }
        0xFF => {
            panic!("Invalid ziplist previous entry lenght")
        }
        _ => {
            first_byte as usize
        }
    }
}

fn read_ziplist_entry_value(buf: &mut dyn Read) -> String {
    decode_special_flag(buf)
}

fn decode_special_flag(buf: &mut dyn Read) -> String {
    let first_byte = buf.read_u8().unwrap();
    match first_byte >> 6 {
        0 => {
            let len = first_byte as usize;
            let mut entry_buf = vec![0u8; len];
            buf.read_exact(&mut entry_buf).unwrap();
            String::from_utf8(entry_buf).unwrap()
        }
        1 => {
            let upper = (first_byte & 0x3F) as usize;
            let lower = buf.read_u8().unwrap() as usize;
            let len = ((upper << 8) + lower) as usize;
            let mut entry_buf = vec![0u8; len];
            buf.read_exact(&mut entry_buf).unwrap();
            String::from_utf8(entry_buf).unwrap()
        }
        2 => {
            let len = buf.read_u32::<BigEndian>().unwrap() as usize;
            let mut entry_buf = vec![0u8; len];
            buf.read_exact(&mut entry_buf).unwrap();
            String::from_utf8(entry_buf).unwrap()
        }
        _ => {
            match first_byte {
                0xC0 => {
                    buf.read_i16::<BigEndian>().unwrap().to_string()
                }
                0xD0 => {
                    buf.read_i32::<BigEndian>().unwrap().to_string()
                }
                0xE0 => {
                    buf.read_i64::<BigEndian>().unwrap().to_string()
                }
                0xF0 => {
                    buf.read_i24::<BigEndian>().unwrap().to_string()
                }
                0xFE => {
                    buf.read_i8().unwrap().to_string()
                }
                0xFF => {
                    panic!("Reached end of ziplist in the middle of entries")
                }
                _ => {
                    ((first_byte & 0x0F) - 1).to_string()
                }
            }
        }
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
        let f = File::open(file).unwrap();
        let reader = BufReader::new(f);
        let mut parser = Parser::new(reader);
        match parser.parse() {
            Ok(_) => println!("It's rdb file"),
            Err(err) => println!("error {}", err)
        }
    }
}
