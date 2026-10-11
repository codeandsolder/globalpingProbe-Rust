use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use ed25519_dalek::{Signer as _, SigningKey};
use globalping_probe::supervisor::update::{
    BehaviorManifest, MAX_COMPONENT_BYTES, MAX_MANIFEST_BYTES, SUPPORTED_ABI_MAJOR,
    SUPPORTED_ABI_MINOR, verify_artifact,
};
use semver::Version;
use sha2::{Digest as _, Sha256};

const MAX_SIGNING_KEY_INPUT_BYTES: usize = 1024;
const MAX_BUILD_ID_BYTES: usize = 128;
const MANIFEST_NAME: &str = "manifest.json";
const COMPONENT_NAME: &str = "component.wasm";

const USAGE: &str = "\
Usage:
  globalping-behavior-pack \\
    --component <component.wasm> \\
    --output-dir <new-directory> \\
    --sequence <positive-u64> \\
    --build-id <id> \\
    --signing-key <hex-seed-file|->

The signing key input must contain exactly 32 Ed25519 seed bytes encoded as
64 hexadecimal characters. Use '-' to read the seed from stdin. The output
directory must not already exist; the packer emits exactly manifest.json and
component.wasm after verifying the signed pair with the production verifier.
";

#[derive(Debug)]
enum SigningKeySource {
    File(PathBuf),
    Stdin,
}

#[derive(Debug)]
struct Args {
    component: PathBuf,
    output_dir: PathBuf,
    sequence: u64,
    build_id: String,
    signing_key: SigningKeySource,
}

#[derive(Debug, PartialEq, Eq)]
struct PackageSummary {
    sequence: u64,
    build_id: String,
    sha256: String,
    verifying_key: String,
    manifest_path: PathBuf,
    component_path: PathBuf,
}

enum ParseOutcome {
    Run(Args),
    Help,
}

fn main() -> Result<()> {
    match parse_args(env::args_os())? {
        ParseOutcome::Help => print!("{USAGE}"),
        ParseOutcome::Run(args) => {
            let summary = package_artifact(&args)?;
            println!("artifact-dir={}", args.output_dir.display());
            println!("manifest={}", summary.manifest_path.display());
            println!("component={}", summary.component_path.display());
            println!("sequence={}", summary.sequence);
            println!("build-id={}", summary.build_id);
            println!("sha256={}", summary.sha256);
            println!("verifying-key={}", summary.verifying_key);
        }
    }
    Ok(())
}

fn parse_args<I>(args: I) -> Result<ParseOutcome>
where
    I: IntoIterator<Item = OsString>,
{
    let mut iter = args.into_iter();
    let _program = iter.next();

    let mut component = None;
    let mut output_dir = None;
    let mut sequence = None;
    let mut build_id = None;
    let mut signing_key = None;

    while let Some(flag) = iter.next() {
        if flag == "--help" || flag == "-h" {
            return Ok(ParseOutcome::Help);
        }

        let flag_text = flag
            .to_str()
            .with_context(|| format!("argument name is not valid UTF-8: {}", flag.display()))?;
        let value = iter
            .next()
            .with_context(|| format!("missing value for {flag_text}"))?;

        match flag_text {
            "--component" => set_once(&mut component, PathBuf::from(value), flag_text)?,
            "--output-dir" => set_once(&mut output_dir, PathBuf::from(value), flag_text)?,
            "--sequence" => {
                let text = os_string_into_utf8(value, flag_text)?;
                let parsed = text
                    .parse::<u64>()
                    .with_context(|| format!("{flag_text} must be an unsigned integer"))?;
                ensure!(parsed > 0, "{flag_text} must be greater than zero");
                set_once(&mut sequence, parsed, flag_text)?;
            }
            "--build-id" => {
                let text = os_string_into_utf8(value, flag_text)?;
                validate_build_id(&text)?;
                set_once(&mut build_id, text, flag_text)?;
            }
            "--signing-key" => {
                let source = if value == OsStr::new("-") {
                    SigningKeySource::Stdin
                } else {
                    SigningKeySource::File(PathBuf::from(value))
                };
                set_once(&mut signing_key, source, flag_text)?;
            }
            _ => bail!("unknown argument {flag_text}"),
        }
    }

    Ok(ParseOutcome::Run(Args {
        component: component.context("missing required --component")?,
        output_dir: output_dir.context("missing required --output-dir")?,
        sequence: sequence.context("missing required --sequence")?,
        build_id: build_id.context("missing required --build-id")?,
        signing_key: signing_key.context("missing required --signing-key")?,
    }))
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<()> {
    ensure!(slot.is_none(), "{flag} may only be specified once");
    *slot = Some(value);
    Ok(())
}

fn os_string_into_utf8(value: OsString, flag: &str) -> Result<String> {
    value
        .into_string()
        .map_err(|value| anyhow::anyhow!("{flag} value is not valid UTF-8: {}", value.display()))
}

fn validate_build_id(build_id: &str) -> Result<()> {
    ensure!(!build_id.is_empty(), "--build-id must not be empty");
    ensure!(
        build_id.len() <= MAX_BUILD_ID_BYTES,
        "--build-id must be at most {MAX_BUILD_ID_BYTES} bytes"
    );
    ensure!(
        build_id.bytes().all(|byte| byte.is_ascii_graphic()),
        "--build-id must contain only printable non-whitespace ASCII"
    );
    Ok(())
}

fn package_artifact(args: &Args) -> Result<PackageSummary> {
    validate_build_id(&args.build_id)?;
    ensure!(args.sequence > 0, "--sequence must be greater than zero");

    let component = fs::read(&args.component)
        .with_context(|| format!("failed to read component {}", args.component.display()))?;
    ensure!(
        component.len() <= MAX_COMPONENT_BYTES,
        "component exceeds the {MAX_COMPONENT_BYTES}-byte supervisor limit"
    );

    let signing_key = read_signing_key(&args.signing_key)?;
    let supervisor_version =
        Version::parse(env!("CARGO_PKG_VERSION")).context("package version is not valid semver")?;
    let digest = Sha256::digest(&component);
    let digest_hex = hex::encode(digest);

    let mut manifest = BehaviorManifest {
        sequence: args.sequence,
        abi_major: SUPPORTED_ABI_MAJOR,
        abi_minor: SUPPORTED_ABI_MINOR,
        min_supervisor_version: env!("CARGO_PKG_VERSION").to_owned(),
        size: u64::try_from(component.len()).context("component size does not fit in u64")?,
        sha256: digest_hex.clone(),
        build_id: args.build_id.clone(),
        signature: String::new(),
    };
    manifest.signature = hex::encode(signing_key.sign(&manifest.signing_payload()).to_bytes());

    verify_artifact(
        manifest.clone(),
        component.clone(),
        &signing_key.verifying_key(),
        &supervisor_version,
    )
    .context("signed artifact failed the production verifier")?;

    let mut manifest_json =
        serde_json::to_vec_pretty(&manifest).context("failed to serialize behavior manifest")?;
    manifest_json.push(b'\n');
    ensure!(
        manifest_json.len() <= MAX_MANIFEST_BYTES,
        "manifest exceeds the {MAX_MANIFEST_BYTES}-byte supervisor limit"
    );

    let manifest_path = args.output_dir.join(MANIFEST_NAME);
    let component_path = args.output_dir.join(COMPONENT_NAME);
    write_new_artifact_directory(
        &args.output_dir,
        &component_path,
        &component,
        &manifest_path,
        &manifest_json,
    )?;

    Ok(PackageSummary {
        sequence: args.sequence,
        build_id: args.build_id.clone(),
        sha256: digest_hex,
        verifying_key: hex::encode(signing_key.verifying_key().to_bytes()),
        manifest_path,
        component_path,
    })
}

fn read_signing_key(source: &SigningKeySource) -> Result<SigningKey> {
    let mut encoded = match source {
        SigningKeySource::File(path) => read_bounded_file(path)?,
        SigningKeySource::Stdin => read_bounded_stdin()?,
    };

    let trimmed_len = trim_ascii_whitespace(&encoded).len();
    if trimmed_len != 64 {
        encoded.fill(0);
        bail!("signing key must contain exactly 64 hexadecimal characters");
    }

    let mut seed = [0_u8; 32];
    let decode_result = {
        let trimmed = trim_ascii_whitespace(&encoded);
        hex::decode_to_slice(trimmed, &mut seed)
    };
    encoded.fill(0);
    if let Err(error) = decode_result {
        seed.fill(0);
        bail!("signing key is not valid hexadecimal: {error}");
    }

    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok(signing_key)
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open signing key {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to stat signing key {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "signing key path is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len()
            <= u64::try_from(MAX_SIGNING_KEY_INPUT_BYTES)
                .context("signing key input limit does not fit in u64")?,
        "signing key input exceeds {MAX_SIGNING_KEY_INPUT_BYTES} bytes"
    );
    read_bounded(file, &format!("signing key {}", path.display()))
}

fn read_bounded_stdin() -> Result<Vec<u8>> {
    read_bounded(io::stdin().lock(), "signing key from stdin")
}

fn read_bounded<R: Read>(reader: R, source: &str) -> Result<Vec<u8>> {
    let limit = u64::try_from(MAX_SIGNING_KEY_INPUT_BYTES + 1)
        .context("signing key input limit does not fit in u64")?;
    let mut input = Vec::new();
    if let Err(error) = reader.take(limit).read_to_end(&mut input) {
        input.fill(0);
        return Err(error).with_context(|| format!("failed to read {source}"));
    }
    if input.len() > MAX_SIGNING_KEY_INPUT_BYTES {
        input.fill(0);
        bail!("signing key input exceeds {MAX_SIGNING_KEY_INPUT_BYTES} bytes");
    }
    Ok(input)
}

fn write_new_artifact_directory(
    output_dir: &Path,
    component_path: &Path,
    component: &[u8],
    manifest_path: &Path,
    manifest: &[u8],
) -> Result<()> {
    fs::create_dir(output_dir).with_context(|| {
        format!(
            "failed to create fresh output directory {}; it must not already exist",
            output_dir.display()
        )
    })?;

    let write_result = (|| -> Result<()> {
        write_synced(component_path, component)?;
        write_synced(manifest_path, manifest)?;
        sync_directory(output_dir)?;
        Ok(())
    })();

    if let Err(error) = write_result {
        let cleanup_result = fs::remove_dir_all(output_dir);
        if let Err(cleanup_error) = cleanup_result {
            return Err(error).context(format!(
                "additionally failed to clean incomplete output directory {}: {cleanup_error}",
                output_dir.display()
            ));
        }
        return Err(error);
    }

    Ok(())
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open output directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync output directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use globalping_probe::supervisor::update::verify_artifact;

    fn test_args(root: &Path) -> Result<Args> {
        let component = root.join("input.wasm");
        fs::write(&component, b"deterministic-test-component")?;

        let key = root.join("signing-key.hex");
        fs::write(&key, format!("{}\n", "47".repeat(32)))?;

        Ok(Args {
            component,
            output_dir: root.join("artifact"),
            sequence: 42,
            build_id: "test-build-42".to_owned(),
            signing_key: SigningKeySource::File(key),
        })
    }

    #[test]
    fn emits_exact_pair_accepted_by_production_verifier() -> Result<()> {
        let root = tempfile::tempdir()?;
        let args = test_args(root.path())?;
        let summary = package_artifact(&args)?;

        let entries = fs::read_dir(&args.output_dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(entries.len(), 2);
        assert!(args.output_dir.join(MANIFEST_NAME).is_file());
        assert!(args.output_dir.join(COMPONENT_NAME).is_file());

        let manifest: BehaviorManifest =
            serde_json::from_slice(&fs::read(&summary.manifest_path)?)?;
        let component = fs::read(&summary.component_path)?;
        let signing_key = SigningKey::from_bytes(&[0x47; 32]);
        let verified = verify_artifact(
            manifest,
            component,
            &signing_key.verifying_key(),
            &Version::parse(env!("CARGO_PKG_VERSION"))?,
        )?;

        assert_eq!(verified.manifest.sequence, 42);
        assert_eq!(verified.manifest.build_id, "test-build-42");
        assert_eq!(verified.manifest.abi_major, SUPPORTED_ABI_MAJOR);
        assert_eq!(verified.manifest.abi_minor, SUPPORTED_ABI_MINOR);
        assert_eq!(
            summary.verifying_key,
            hex::encode(signing_key.verifying_key().to_bytes())
        );
        Ok(())
    }

    #[test]
    fn refuses_to_mix_with_an_existing_output_directory() -> Result<()> {
        let root = tempfile::tempdir()?;
        let args = test_args(root.path())?;
        fs::create_dir(&args.output_dir)?;

        let error = package_artifact(&args)
            .err()
            .context("packaging unexpectedly succeeded")?;
        assert!(error.to_string().contains("must not already exist"));
        Ok(())
    }

    #[test]
    fn rejects_zero_sequence_and_unsafe_build_id() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut args = test_args(root.path())?;
        args.sequence = 0;
        let error = package_artifact(&args)
            .err()
            .context("zero sequence unexpectedly succeeded")?;
        assert!(error.to_string().contains("greater than zero"));

        args.sequence = 1;
        args.build_id = "line\nbreak".to_owned();
        let error = package_artifact(&args)
            .err()
            .context("unsafe build id unexpectedly succeeded")?;
        assert!(error.to_string().contains("printable non-whitespace ASCII"));
        Ok(())
    }

    #[test]
    fn rejects_malformed_signing_key() -> Result<()> {
        let root = tempfile::tempdir()?;
        let args = test_args(root.path())?;
        let key_path = match &args.signing_key {
            SigningKeySource::File(path) => path,
            SigningKeySource::Stdin => bail!("test unexpectedly configured stdin"),
        };
        fs::write(key_path, "abcd\n")?;

        let error = package_artifact(&args)
            .err()
            .context("malformed signing key unexpectedly succeeded")?;
        assert!(error.to_string().contains("64 hexadecimal characters"));
        Ok(())
    }
}
