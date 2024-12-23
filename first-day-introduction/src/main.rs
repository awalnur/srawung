use std::fs::File;
use std::io;
use std::io::Read;

fn read_content()-> io::Result<String> {
    let mut x = File::open("hello.txt").expect("Failed to open hello.txt");
    let mut buffer = [0, 128];
    let mut text = String::new();
    loop {
        let n = x.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        text.push_str(&String::from_utf8_lossy(&buffer[..n]));
    }
    Ok(text)
}
fn main() -> Result<(), std::io::Error> {

    let content = read_content()?;
    println!("{}", content);
    Ok(())
}
