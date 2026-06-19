use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process,
};
use zeroize::Zeroizing;

#[derive(Clone, ValueEnum)]
enum Algorithm {
    Argon2d,
    Argon2i,
    Argon2id,
}

impl From<Algorithm> for argon2::Algorithm {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::Argon2d => argon2::Algorithm::Argon2d,
            Algorithm::Argon2i => argon2::Algorithm::Argon2i,
            Algorithm::Argon2id => argon2::Algorithm::Argon2id,
        }
    }
}

#[derive(Parser)]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(flatten)]
    generate: GenerateArgs,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Generate(GenerateArgs),
    Verify(VerifyArgs),
}

#[derive(Parser, Clone)]
struct GenerateArgs {
    #[arg(
        short = 'a',
        long,
        env = "ARGON2_ALGORITHM",
        default_value = "argon2id",
        value_enum
    )]
    algorithm: Algorithm,

    #[arg(short = 'm', long, env = "ARGON2_MEMORY", default_value_t = 65536)]
    memory: u32,

    #[arg(short = 't', long, env = "ARGON2_ITERATIONS", default_value_t = 4)]
    iterations: u32,

    #[arg(short = 'p', long, env = "ARGON2_PARALLELISM", default_value_t = 1)]
    parallelism: u32,
}

#[derive(Parser, Clone)]
struct VerifyArgs {
    #[arg(long, conflicts_with = "file")]
    hash: Option<String>,

    #[arg(long)]
    file: Option<PathBuf>,

    #[arg(long, default_value = "\t")]
    separator: String,
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Match,
    Mismatch,
    Error(String),
}

fn generate_hash(args: &GenerateArgs, password: &[u8]) -> Result<String, String> {
    let params = Params::new(args.memory, args.iterations, args.parallelism, Some(32))
        .map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(args.algorithm.clone().into(), Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| e.to_string())?;
    Ok(hash.to_string())
}

fn verify_one(hash: &str, password: &[u8]) -> Outcome {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(e) => return Outcome::Error(e.to_string()),
    };
    match Argon2::default().verify_password(password, &parsed) {
        Ok(()) => Outcome::Match,
        Err(argon2::password_hash::Error::Password) => Outcome::Mismatch,
        Err(e) => Outcome::Error(e.to_string()),
    }
}

fn validate_separator(sep: &str) -> Result<(), String> {
    if sep.is_empty() {
        return Err("separator must not be empty".into());
    }
    let phc_chars: &[char] = &[
        '$', ',', '=', '+', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e',
        'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
        'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    ];
    for ch in sep.chars() {
        if phc_chars.contains(&ch) {
            return Err(format!("separator {:?} collides with PHC characters", sep));
        }
    }
    Ok(())
}

fn parse_line<'a>(line: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    line.split_once(sep)
}

fn prompt_password() -> Result<Zeroizing<String>, String> {
    rpassword::prompt_password("Enter Password: ")
        .map(Zeroizing::new)
        .map_err(|e| e.to_string())
}

fn run_generate(args: &GenerateArgs) -> i32 {
    let password = match prompt_password() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    match generate_hash(args, password.as_bytes()) {
        Ok(hash) => {
            println!("{hash}");
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    }
}

struct BatchResult {
    lineno: usize,
    outcome: Outcome,
}

fn process_batch(content: &str, separator: &str) -> (Vec<BatchResult>, i32) {
    let mut results = Vec::new();
    let mut any_mismatch = false;
    let mut any_error = false;

    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let lineno = i + 1;
        let outcome = match parse_line(line, separator) {
            None => Outcome::Error(format!("line {lineno}: malformed (no separator)")),
            Some((hash, pw)) => {
                let pw_z = Zeroizing::new(pw.to_owned());
                verify_one(hash, pw_z.as_bytes())
            }
        };
        match &outcome {
            Outcome::Mismatch => any_mismatch = true,
            Outcome::Error(_) => any_error = true,
            Outcome::Match => {}
        }
        results.push(BatchResult { lineno, outcome });
    }

    let code = if any_error {
        2
    } else if any_mismatch {
        1
    } else {
        0
    };
    (results, code)
}

fn run_verify(args: &VerifyArgs) -> i32 {
    if let Err(e) = validate_separator(&args.separator) {
        eprintln!("error: {e}");
        return 2;
    }

    match (&args.hash, &args.file) {
        (Some(hash), None) => {
            let password = match prompt_password() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            };
            match verify_one(hash, password.as_bytes()) {
                Outcome::Match => {
                    println!("MATCH");
                    0
                }
                Outcome::Mismatch => {
                    println!("NO MATCH");
                    1
                }
                Outcome::Error(e) => {
                    eprintln!("error: {e}");
                    2
                }
            }
        }
        (None, Some(path)) => {
            let content = match fs::read_to_string(path) {
                Ok(c) => Zeroizing::new(c),
                Err(e) => {
                    eprintln!("error reading {}: {e}", path.display());
                    return 2;
                }
            };
            let (results, code) = process_batch(&content, &args.separator);
            let matched = results
                .iter()
                .filter(|r| r.outcome == Outcome::Match)
                .count();
            let total = results.len();
            for r in &results {
                match &r.outcome {
                    Outcome::Match => println!("line {}: MATCH", r.lineno),
                    Outcome::Mismatch => println!("line {}: NO MATCH", r.lineno),
                    Outcome::Error(e) => eprintln!("error: {e}"),
                }
            }
            println!("{matched}/{total} matched");
            code
        }
        _ => {
            eprintln!("error: provide --hash <PHC> or --file <PATH>");
            2
        }
    }
}

fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Generate(args)) => run_generate(&args),
        Some(Commands::Verify(args)) => run_verify(&args),
        None => run_generate(&cli.generate),
    }
}

fn main() {
    let _ = io::stdout().flush();
    process::exit(run());
}

#[cfg(test)]
mod tests;
