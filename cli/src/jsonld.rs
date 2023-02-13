use std::io::{stdin, stdout, BufReader, Read, Write};

use anyhow::Result;
use clap::{Args, Subcommand};
use didkit::ssi::{
    self,
    jsonld::{parse_ld_context, StaticLoader},
    rdf,
};
use iref::IriBuf;
use json_ld::JsonLdProcessor;
use serde_json::json;

#[derive(Subcommand)]
pub enum JsonldCmd {
    /// Convert JSON-LD documents to other formats
    #[clap(subcommand)]
    To(JsonldToCmd),
}

#[derive(Subcommand)]
pub enum JsonldToCmd {
    /// Convert to URDNA2015-canonicalized RDF N-Quads
    Rdfurdna(JsonldToRDFURDNAArgs),
}

#[derive(Args)]
pub struct JsonldToRDFURDNAArgs {
    /// Base IRI
    #[clap(short = 'b', long)]
    base: Option<String>,
    /// IRI for expandContext option
    #[clap(short = 'c', long)]
    expand_context: Option<String>,
    /// Additional values for JSON-LD @context property.
    #[clap(short = 'C', long)]
    more_context_json: Option<String>,
}

pub async fn cli(cmd: JsonldCmd) -> Result<()> {
    match cmd {
        JsonldCmd::To(cmd_to) => to(cmd_to).await?,
    };
    Ok(())
}

pub async fn to(cmd: JsonldToCmd) -> Result<()> {
    match cmd {
        JsonldToCmd::Rdfurdna(cmd) => to_rdfurdna(cmd).await?,
    };
    Ok(())
}

pub async fn to_rdfurdna(args: JsonldToRDFURDNAArgs) -> Result<()> {
    let mut loader = StaticLoader;
    let expand_context = if let Some(m_c) = args.more_context_json {
        if let Some(e_c) = args.expand_context {
            Some(
                serde_json::to_string(&json!([
                    e_c,
                    serde_json::from_str::<serde_json::Value>(&m_c).unwrap()
                ]))
                .unwrap(),
            )
        } else {
            Some(m_c)
        }
    } else {
        args.expand_context
    };
    let mut reader = BufReader::new(stdin());
    let mut json = String::new();
    reader.read_to_string(&mut json).unwrap();
    let json = ssi::jsonld::syntax::to_value_with(
        serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        Default::default,
    )
    .unwrap();
    let expand_context = expand_context.map(|c| parse_ld_context(&c).unwrap());
    // Implementation of `ssi::jsonld::json_to_dataset`
    let options = ssi::jsonld::Options {
        base: args.base.map(|b| IriBuf::from_string(b).unwrap()),
        expand_context,
        ..Default::default()
    };
    let doc = ssi::jsonld::RemoteDocument::new(None, None, json);
    let mut generator =
        rdf_types::generator::Blank::new_with_prefix("b".to_string()).with_default_metadata();
    let mut to_rdf = doc
        .to_rdf_using(&mut generator, &mut loader, options)
        .await
        .map_err(Box::new)
        .unwrap();
    let dataset: rdf::DataSet = to_rdf
        .cloned_quads()
        .map(|q| q.map_predicate(|p| p.into_iri().unwrap()))
        .collect();
    let dataset_normalized = ssi::urdna2015::normalize(dataset.quads().map(Into::into));
    let normalized = dataset_normalized.into_nquads();
    stdout().write_all(normalized.as_bytes()).unwrap();
    Ok(())
}
