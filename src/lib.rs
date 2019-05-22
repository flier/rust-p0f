#[macro_use]
extern crate log;

use core::fmt;

pub mod db;
pub mod http;
mod parse;
pub mod tcp;

#[derive(Clone, Debug, PartialEq)]
pub struct Label {
    pub ty: Type,
    pub class: Option<String>,
    pub name: String,
    pub flavor: Option<String>,
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            match self.ty {
                Type::Specified => "s",
                Type::Generic => "g",
            },
            self.class.as_ref().map(|s| s.as_str()).unwrap_or_default(),
            self.name,
            self.flavor.as_ref().map(|s| s.as_str()).unwrap_or_default()
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    Specified,
    Generic,
}
