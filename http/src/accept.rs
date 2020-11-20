use std::collections::HashMap;
use std::str::FromStr;

use crate::Error;

// HTTP Accept header
// https://tools.ietf.org/html/rfc2616#section-14.1

// https://tools.ietf.org/html/rfc2616#page-100
//
//       Accept         = "Accept" ":"
//                        #( media-range [ accept-params ] )
//
//       media-range    = ( "*/*"
//                        | ( type "/" "*" )
//                        | ( type "/" subtype )
//                        ) *( ";" parameter )
//       accept-params  = ";" "q" "=" qvalue *( accept-extension )
//       accept-extension = ";" token [ "=" ( token | quoted-string ) ]

// https://tools.ietf.org/html/rfc2616#page-17
//
//       token          = 1*<any CHAR except CTLs or separators>
//       separators     = "(" | ")" | "<" | ">" | "@"
//                       | "," | ";" | ":" | "\" | <">
//                       | "/" | "[" | "]" | "?" | "="
//                       | "{" | "}" | SP | HT
//
//       quoted-string  = ( <"> *(qdtext | quoted-pair ) <"> )
//       qdtext         = <any TEXT except <">>
//       quoted-pair    = "\" CHAR

#[derive(Debug, Clone, PartialEq)]
pub struct Parameters(pub HashMap<String, String>);

impl FromStr for Parameters {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split(';').map(|s| s.trim());
        // TODO: handle quoted values containing semicolons or commas
        let mut this = Self::default();
        for part in parts {
            let mut kvparts = part.splitn(2, '=');
            if let (Some(key), Some(val)) = (kvparts.next(), kvparts.next()) {
                let (key, val) = (key.trim(), val.trim().to_string());
                this.insert_unquoted(key, val);
            }
        }
        Ok(this)
    }
}

impl Parameters {
    fn insert_unquoted(&mut self, key: &str, mut val: String) {
        let mut chars = val.chars();
        if chars.next() == Some('"') && chars.next_back() == Some('"') {
            // TODO: unescape quotes
            val = chars.collect();
        }
        self.0.insert(key.to_string(), val);
    }

    pub fn matches(&self, other: &Self) -> bool {
        return other
            .0
            .iter()
            .all(|(key, val)| self.0.get(key) == Some(val));
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self(HashMap::new())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MediaTypeRange {
    /// "*/*"
    All,
    /// "type/*"
    Range { type_: String },
    /// "type/subtype"
    Type { type_: String, subtype: String },
}

impl FromStr for MediaTypeRange {
    type Err = Error;
    fn from_str(range: &str) -> Result<Self, Self::Err> {
        let mut parts = range.splitn(2, '/');
        Ok(match (parts.next(), parts.next()) {
            (Some("*"), Some("*")) => Self::All,
            (Some(type_), Some("*")) => Self::Range {
                type_: type_.to_string(),
            },
            (Some(type_), Some(subtype)) => Self::Type {
                type_: type_.to_string(),
                subtype: subtype.to_string(),
            },
            _ => return Err(Error::InvalidAccept),
        })
    }
}

impl MediaTypeRange {
    pub fn matches(&self, type_: &str, subtype: &str) -> bool {
        match self {
            Self::All => true,
            Self::Range { type_: stype } => stype == type_,
            Self::Type {
                type_: stype,
                subtype: ssubtype,
            } => stype == type_ && subtype == ssubtype,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MediaRange {
    range: MediaTypeRange,
    parameters: Parameters,
}

impl MediaRange {
    pub fn matches(&self, type_: &str, subtype: &str, params: &Parameters) -> bool {
        if !self.range.matches(type_, subtype) {
            return false;
        }
        self.parameters.matches(params)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HttpAcceptItem {
    range: MediaRange,
    qvalue: Option<f32>,
    parameters: Parameters,
}

impl FromStr for HttpAcceptItem {
    type Err = Error;
    fn from_str(item: &str) -> Result<Self, Self::Err> {
        let mut media_type_parameters = Parameters::default();
        let mut accept_extension_parameters = Parameters::default();
        let mut parts = item.split(';').map(|s| s.trim());
        let media_part = match parts.next() {
            Some(part) => part,
            None => return Err(Error::InvalidAccept),
        };
        let mut in_extensions = false;
        let mut qvalue = None;
        for part in parts {
            let mut kvparts = part.splitn(2, '=');
            if let (Some(key), Some(val)) = (kvparts.next(), kvparts.next()) {
                let (key, val) = (key.trim(), val.trim().to_string());
                if in_extensions {
                    accept_extension_parameters.insert_unquoted(key, val);
                } else if key == "q" {
                    qvalue.replace(val.parse()?);
                    in_extensions = true;
                } else {
                    media_type_parameters.insert_unquoted(key, val);
                }
            }
        }
        Ok(Self {
            range: MediaRange {
                range: media_part.parse()?,
                parameters: media_type_parameters,
            },
            qvalue: qvalue,
            parameters: accept_extension_parameters,
        })
    }
}

impl HttpAcceptItem {
    pub fn matches(&self, type_: &str, subtype: &str, params: &Parameters) -> bool {
        let qvalue = self.qvalue.unwrap_or(1_f32);
        if qvalue == 0_f32 {
            return false;
        }
        self.range.matches(type_, subtype, params)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HttpAccept {
    parts: Vec<HttpAcceptItem>,
}

impl FromStr for HttpAccept {
    type Err = Error;
    fn from_str(accept: &str) -> Result<Self, Self::Err> {
        let parts = accept
            .split(",")
            .map(|s| s.parse())
            .collect::<Result<Vec<HttpAcceptItem>, Error>>()?;
        Ok(Self { parts })
    }
}

impl HttpAccept {
    pub fn can_accept(&self, content_type: &str) -> bool {
        let mut param_parts = content_type.splitn(2, ';');
        let media_part = match param_parts.next() {
            Some(part) => part,
            None => return false,
        };
        let params = match match param_parts.next() {
            Some(s) => s.parse(),
            None => Ok(Parameters::default()),
        } {
            Ok(params) => params,
            Err(_) => return false,
        };
        let mut type_parts = media_part.splitn(2, '/');
        let (type_, subtype) = match (type_parts.next(), type_parts.next()) {
            (Some(a), Some(b)) => (a, b),
            _ => return false,
        };
        self.parts
            .iter()
            .any(|part| part.matches(type_, subtype, &params))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rfc2616_examples() {
        // https://tools.ietf.org/html/rfc2616#page-101
        let accept = HttpAccept::from_str("audio/*; q=0.2, audio/basic").unwrap();
        assert_eq!(
            accept,
            HttpAccept {
                parts: vec![
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Range {
                                type_: "audio".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: Some(0.2_f32),
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "audio".to_string(),
                                subtype: "basic".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: None,
                        parameters: Parameters::default()
                    }
                ]
            }
        );

        let accept =
            HttpAccept::from_str("text/plain; q=0.5, text/html, text/x-dvi; q=0.8, text/x-c")
                .unwrap();
        assert_eq!(
            accept,
            HttpAccept {
                parts: vec![
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "text".to_string(),
                                subtype: "plain".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: Some(0.5_f32),
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "text".to_string(),
                                subtype: "html".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: None,
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "text".to_string(),
                                subtype: "x-dvi".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: Some(0.8_f32),
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "text".to_string(),
                                subtype: "x-c".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: None,
                        parameters: Parameters::default()
                    }
                ]
            }
        );

        let accept = HttpAccept::from_str("text/*, text/html, text/html;level=1, */*").unwrap();
        assert_eq!(
            accept,
            HttpAccept {
                parts: vec![
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Range {
                                type_: "text".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: None,
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "text".to_string(),
                                subtype: "html".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: None,
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "text".to_string(),
                                subtype: "html".to_string()
                            },
                            parameters: Parameters(
                                vec![("level".to_string(), "1".to_string())]
                                    .into_iter()
                                    .collect()
                            )
                        },
                        qvalue: None,
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::All,
                            parameters: Parameters::default()
                        },
                        qvalue: None,
                        parameters: Parameters::default()
                    }
                ]
            }
        );

        let accept = HttpAccept::from_str(
            "text/*;q=0.3, text/html;q=0.7, text/html;level=1, text/html;level=2;q=0.4, */*;q=0.5",
        )
        .unwrap();
        assert_eq!(
            accept,
            HttpAccept {
                parts: vec![
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Range {
                                type_: "text".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: Some(0.3_f32),
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "text".to_string(),
                                subtype: "html".to_string()
                            },
                            parameters: Parameters::default()
                        },
                        qvalue: Some(0.7_f32),
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "text".to_string(),
                                subtype: "html".to_string()
                            },
                            parameters: Parameters(
                                vec![("level".to_string(), "1".to_string())]
                                    .into_iter()
                                    .collect()
                            )
                        },
                        qvalue: None,
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::Type {
                                type_: "text".to_string(),
                                subtype: "html".to_string()
                            },
                            parameters: Parameters(
                                vec![("level".to_string(), "2".to_string())]
                                    .into_iter()
                                    .collect()
                            )
                        },
                        qvalue: Some(0.4_f32),
                        parameters: Parameters::default()
                    },
                    HttpAcceptItem {
                        range: MediaRange {
                            range: MediaTypeRange::All,
                            parameters: Parameters::default()
                        },
                        qvalue: Some(0.5_f32),
                        parameters: Parameters::default()
                    }
                ]
            }
        );
    }

    #[test]
    fn parse_did_resolution() {
        // https://w3c-ccg.github.io/did-resolution/
        let did_resolution_type = "application/ld+json;profile=\"https://w3id.org/did-resolution\"";
        let accept = HttpAccept::from_str(did_resolution_type).unwrap();
        assert_eq!(
            accept,
            HttpAccept {
                parts: vec![HttpAcceptItem {
                    range: MediaRange {
                        range: MediaTypeRange::Type {
                            type_: "application".to_string(),
                            subtype: "ld+json".to_string()
                        },
                        parameters: Parameters(
                            vec![(
                                "profile".to_string(),
                                "https://w3id.org/did-resolution".to_string()
                            )]
                            .into_iter()
                            .collect()
                        )
                    },
                    qvalue: None,
                    parameters: Parameters::default()
                }]
            }
        );
    }
}
