#[macro_use]
extern crate log;

pub mod db;
pub mod http;
pub mod tcp;

#[cfg(feature = "display")]
mod display;
#[cfg(feature = "packet")]
mod packet;
#[cfg(feature = "parse")]
mod parse;

#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub ty: Type,
    pub class: Option<String>,
    pub name: String,
    pub flavor: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    Specified,
    Generic,
}
