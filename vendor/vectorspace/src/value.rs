use crate::ast::VectorType;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(u128),
    String(String),
    Path(Vec<String>),
    Map(BTreeMap<String, Value>),
    Vector(Vec<u128>),
    Type(VectorType),
}

impl Value {
    pub fn as_int(&self) -> Option<u128> {
        match self {
            Value::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            Value::String(v) => Some(v),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub fields: BTreeMap<String, Value>,
}

impl Context {
    pub fn new() -> Self {
        Self { fields: BTreeMap::new() }
    }

    pub fn with(mut self, key: impl Into<String>, value: Value) -> Self {
        self.fields.insert(key.into(), value);
        self
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }
}
