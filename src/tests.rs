use super::*;

fn default_generate_args() -> GenerateArgs {
    GenerateArgs {
        algorithm: Algorithm::Argon2id,
        memory: 65536,
        iterations: 4,
        parallelism: 1,
    }
}

#[test]
fn parse_line_basic() {
    let result = parse_line("somehash\tthepassword", "\t");
    assert_eq!(result, Some(("somehash", "thepassword")));
}

#[test]
fn parse_line_password_contains_separator() {
    let result = parse_line("somehash\tpass\tword", "\t");
    assert_eq!(result, Some(("somehash", "pass\tword")));
}

#[test]
fn parse_line_no_separator() {
    let result = parse_line("noseparatorhere", "\t");
    assert_eq!(result, None);
}

#[test]
fn round_trip_match() {
    let args = default_generate_args();
    let hash = generate_hash(&args, b"correct-horse").expect("generate failed");
    assert_eq!(verify_one(&hash, b"correct-horse"), Outcome::Match);
}

#[test]
fn round_trip_wrong_password() {
    let args = default_generate_args();
    let hash = generate_hash(&args, b"correct-horse").expect("generate failed");
    assert_eq!(verify_one(&hash, b"wrong-horse"), Outcome::Mismatch);
}

#[test]
fn verify_malformed_hash() {
    let outcome = verify_one("not-a-phc-string", b"anything");
    assert!(matches!(outcome, Outcome::Error(_)));
}

#[test]
fn separator_rejects_phc_chars() {
    for s in ["=", "$", ",", "A", "+", "/", "a", "0"] {
        assert!(validate_separator(s).is_err(), "should reject: {s}");
    }
}

#[test]
fn separator_rejects_empty() {
    assert!(validate_separator("").is_err());
}

#[test]
fn separator_accepts_safe_chars() {
    for s in ["\t", ":", "|", " ", "::"] {
        assert!(validate_separator(s).is_ok(), "should accept: {s:?}");
    }
}

#[test]
fn batch_all_match() {
    let args = default_generate_args();
    let h1 = generate_hash(&args, b"alpha").unwrap();
    let h2 = generate_hash(&args, b"beta").unwrap();
    let content = format!("{h1}\talpha\n{h2}\tbeta\n");
    let (results, code) = process_batch(&content, "\t");
    assert_eq!(code, 0);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.outcome == Outcome::Match));
}

#[test]
fn batch_mismatch() {
    let args = default_generate_args();
    let h1 = generate_hash(&args, b"alpha").unwrap();
    let h2 = generate_hash(&args, b"beta").unwrap();
    let content = format!("{h1}\talpha\n{h2}\twrong\n");
    let (results, code) = process_batch(&content, "\t");
    assert_eq!(code, 1);
    assert_eq!(results[0].outcome, Outcome::Match);
    assert_eq!(results[1].outcome, Outcome::Mismatch);
}

#[test]
fn batch_malformed_line() {
    let args = default_generate_args();
    let h1 = generate_hash(&args, b"alpha").unwrap();
    let content = format!("{h1}\talpha\nno-separator-here\n");
    let (results, code) = process_batch(&content, "\t");
    assert_eq!(code, 2);
    assert_eq!(results[0].outcome, Outcome::Match);
    assert!(matches!(results[1].outcome, Outcome::Error(_)));
}

#[test]
fn batch_mismatch_and_malformed_precedence() {
    let args = default_generate_args();
    let h1 = generate_hash(&args, b"alpha").unwrap();
    let content = format!("{h1}\twrong\nno-separator-here\n");
    let (_, code) = process_batch(&content, "\t");
    assert_eq!(code, 2);
}

#[test]
fn batch_blank_lines_skipped() {
    let args = default_generate_args();
    let h1 = generate_hash(&args, b"alpha").unwrap();
    let content = format!("\n   \n{h1}\talpha\n\n");
    let (results, code) = process_batch(&content, "\t");
    assert_eq!(code, 0);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].outcome, Outcome::Match);
}
