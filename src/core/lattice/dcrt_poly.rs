use crate::constants::PolynomialRingFormat;
use crate::core::lattice::params::DcrtElementParams;
use crate::core::lattice::poly::Poly;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct DcrtPoly {
    params: DcrtElementParams,
    format: PolynomialRingFormat,
    values: Vec<Poly>,
}
