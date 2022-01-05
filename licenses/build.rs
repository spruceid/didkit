use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, Read, Write};

#[derive(Debug)]
struct Pkg {
    pub name: String,
    pub version: String,
    pub license: String,
    pub path: Option<String>,
    pub url: Option<String>,
}

fn normalize_license(license: String) -> Result<String, String> {
    Ok(match &license[..] {
        "Apache-2.0" => license,
        "MIT" => license,
        "ISC" => license,
        "CC0-1.0" => license,
        "BSD-2-Clause" => license,
        "BSD-3-Clause" => license,
        "MIT/Apache-2.0" | "Apache-2.0 / MIT" | "Apache-2.0/MIT" | "MIT / Apache-2.0"
        | "Apache-2.0 OR MIT" | "MIT OR Apache-2.0" => "MIT OR Apache-2.0".to_string(),
        "MIT OR Zlib OR Apache-2.0" | "Zlib OR Apache-2.0 OR MIT" | "MIT OR Apache-2.0 OR Zlib" => {
            "MIT OR Apache-2.0 OR Zlib".to_string()
        }
        "Apache-2.0 OR BSL-1.0" => license,
        "Unlicense/MIT" | "Unlicense OR MIT" => "Unlicense OR MIT".to_string(),
        "Apache-2.0 AND W3C-20150513 AND CC-BY-SA-3.0" => license,
        "MIT OR Apache-2.0 OR BSD-2-Clause" => license,
        "0BSD OR MIT OR Apache-2.0" => license,
        "MPL-2.0" => license,
        "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT" => license,
        "Ring" => license,
        _ => Err(license)?,
    })
}

fn fix_license(name: &str, version: &str) -> Option<&'static str> {
    match (name, version) {
        ("sshkeys", "v0.3.1") => Some("BSD-2-Clause"),
        ("ring", "v0.16.20") => Some("Ring"),
        ("fuchsia-cprng", "v0.1.1") => Some("BSD-3-Clause"),
        _ => None,
    }
}

fn main() -> std::io::Result<()> {
    let mut out = File::create("licenses.txt")?;
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-changed
    println!("cargo:rerun-if-changed=didkit.tree");
    println!("cargo:rerun-if-changed=std.tree");
    println!("cargo:rerun-if-changed=text/");

    let mut seen = HashSet::new();
    let mut pkgs = Vec::new();
    let mut fail = false;
    let didkit_tree_file = File::open("didkit.tree")?;
    let std_tree_file = File::open("std.tree")?;
    let trees = didkit_tree_file.chain(std_tree_file);
    let reader = std::io::BufReader::new(trees);
    for line in reader.lines() {
        let line = line?;
        if seen.contains(&line) {
            continue;
        }
        seen.insert(line.to_string());
        let mut words = line.split(" ");
        let name = words.next().unwrap().to_string();
        let version = words.next().unwrap().to_string();
        let next = words.next().unwrap();
        let (path, url) = if next.chars().nth(0) == Some('(') {
            let path = next[1..(next.len() - 1)].to_string();
            let next = words.next().unwrap().to_string();
            (Some(path), next)
        } else {
            (None, next.to_string())
        };
        let url = if url == "" { None } else { Some(url) };
        let mut license = words.collect::<Vec<&str>>().join(" ");
        if license == "" {
            if let Some(l) = fix_license(&name, &version) {
                license = l.to_string();
            } else {
                eprintln!("Missing license for pkg: {} {}", name, version);
                fail = true;
                continue;
            }
        }
        let license = match normalize_license(license) {
            Ok(license) => license,
            Err(license) => {
                eprintln!("Unrecognized license string: {}", license);
                fail = true;
                continue;
            }
        };
        let pkg = Pkg {
            name,
            version,
            license,
            path,
            url,
        };
        pkgs.push(pkg);
    }
    if fail {
        std::process::exit(1);
    }
    let mut licenses = HashSet::new();
    let mut pkgs_by_license = HashMap::new();
    for pkg in pkgs {
        let license = pkg.license.to_string();
        for license_option in license.split(" OR ") {
            for license in license_option.split(" AND ") {
                if !licenses.contains(license) {
                    licenses.insert(license.to_string());
                }
            }
            if !licenses.contains(license_option) {
                licenses.insert(license_option.to_string());
            }
        }
        pkgs_by_license
            .entry(license)
            .or_insert_with(HashMap::new)
            .insert(pkg.name.to_string(), pkg);
    }
    writeln!(&mut out, "# DIDKit Licenses")?;
    writeln!(&mut out, "## Packages by license")?;
    let mut licenses_vec = pkgs_by_license.keys().collect::<Vec<_>>();
    licenses_vec.sort();
    for license in licenses_vec {
        let pkgs = pkgs_by_license.get(license).unwrap();
        let mut pkg_names = pkgs.keys().collect::<Vec<_>>();
        pkg_names.sort();
        writeln!(&mut out, "- {}", license)?;
        for pkg_name in pkg_names {
            let pkg = pkgs.get(pkg_name).unwrap();
            writeln!(&mut out, "  - {} {}", pkg.name, pkg.version)?;
        }
    }
    writeln!(&mut out, "")?;
    writeln!(&mut out, "## Licenses")?;
    writeln!(&mut out, "")?;
    let mut licenses_vec = licenses.into_iter().collect::<Vec<_>>();
    licenses_vec.sort();
    for license in licenses_vec {
        writeln!(&mut out, "### {}", license)?;
        writeln!(&mut out, "```")?;
        let license_filename = match &license[..] {
            "Apache-2.0 AND W3C-20150513 AND CC-BY-SA-3.0" => {
                writeln!(&mut out, include_str!("../../ssi/contexts/LICENSES.md"))?;
                continue;
            }
            "Apache-2.0 WITH LLVM-exception" => {
                writeln!(&mut out, include_str!("text/LLVM-exception.txt"))?;
                continue;
            }
            "Apache-2.0" => {
                writeln!(&mut out, include_str!("../LICENSE"))?;
                continue;
            }
            _ => format!("text/{}.txt", license),
        };
        let mut file = File::open(license_filename)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        out.write_all(&buf)?;
        write!(&mut out, "```\n\n")?;
    }
    Ok(())
}
