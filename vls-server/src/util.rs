use serde::ser::SerializeSeq;
use serde::Serializer;

pub fn as_hex<S>(buf: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(&buf))
}

// used in build.rs
#[allow(unused)]
pub fn as_hex_vec<S>(vec: &Vec<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(vec.len()))?;
    for vv in vec {
        seq.serialize_element(&hex::encode(&vv))?;
    }
    seq.end()
}
