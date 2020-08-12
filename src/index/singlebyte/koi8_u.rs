// AUTOGENERATED FROM index-koi8-u.txt, ORIGINAL COMMENT FOLLOWS:
//
// For details on index index-koi8-u.txt see the Encoding Standard
// https://encoding.spec.whatwg.org/
//
// Identifier: 19a4da2c3f245118bbc8019326f45a07832949938ff903f03d62ac4da1f61f40
// Date: 2018-01-06

#[allow(dead_code)] const X: u16 = 0xffff;

const FORWARD_TABLE: &'static [u16] = &[
    9472, 9474, 9484, 9488, 9492, 9496, 9500, 9508, 9516, 9524, 9532, 9600,
    9604, 9608, 9612, 9616, 9617, 9618, 9619, 8992, 9632, 8729, 8730, 8776,
    8804, 8805, 160, 8993, 176, 178, 183, 247, 9552, 9553, 9554, 1105, 1108,
    9556, 1110, 1111, 9559, 9560, 9561, 9562, 9563, 1169, 1118, 9566, 9567,
    9568, 9569, 1025, 1028, 9571, 1030, 1031, 9574, 9575, 9576, 9577, 9578,
    1168, 1038, 169, 1102, 1072, 1073, 1094, 1076, 1077, 1092, 1075, 1093,
    1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1103, 1088, 1089, 1090,
    1091, 1078, 1074, 1100, 1099, 1079, 1096, 1101, 1097, 1095, 1098, 1070,
    1040, 1041, 1062, 1044, 1045, 1060, 1043, 1061, 1048, 1049, 1050, 1051,
    1052, 1053, 1054, 1055, 1071, 1056, 1057, 1058, 1059, 1046, 1042, 1068,
    1067, 1047, 1064, 1069, 1065, 1063, 1066,
]; // 128 entries

/// Returns the index code point for pointer `code` in this index.
#[inline]
pub fn forward(code: u8) -> u16 {
    FORWARD_TABLE[(code - 0x80) as usize]
}

#[cfg(not(feature = "no-optimized-legacy-encoding"))]
const BACKWARD_TABLE_LOWER: &'static [u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 210, 211, 212, 213, 198, 200,
    195, 222, 219, 221, 223, 217, 216, 220, 192, 209, 0, 163, 0, 0, 164, 0,
    166, 167, 0, 0, 0, 0, 0, 0, 174, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 147, 155, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 189, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 159, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 129, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 130, 0, 0, 0, 131, 0, 0, 0, 132, 0, 0, 0, 133, 0,
    0, 0, 134, 0, 0, 0, 0, 0, 0, 0, 135, 0, 0, 0, 0, 0, 0, 0, 136, 0, 0, 0, 0,
    0, 0, 0, 137, 0, 0, 0, 0, 0, 0, 0, 138, 0, 0, 0, 139, 0, 0, 0, 140, 0, 0,
    0, 141, 0, 0, 0, 142, 0, 0, 0, 143, 144, 145, 146, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 149, 150, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 154, 0, 0, 0, 0, 0, 0, 0, 0, 191, 0, 0, 0, 0, 0, 0, 156, 0, 157, 0,
    0, 0, 0, 158, 0, 0, 0, 0, 0, 0, 0, 0, 151, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 152, 153, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 161, 162,
    0, 165, 0, 0, 168, 169, 170, 171, 172, 0, 0, 175, 176, 177, 178, 0, 181, 0,
    0, 184, 185, 186, 187, 188, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 179, 0, 0, 180, 0, 182, 183, 0, 0, 0, 0, 0, 0, 190, 0, 225,
    226, 247, 231, 228, 229, 246, 250, 233, 234, 235, 236, 237, 238, 239, 240,
    242, 243, 244, 245, 230, 232, 227, 254, 251, 253, 255, 249, 248, 252, 224,
    241, 193, 194, 215, 199, 196, 197, 214, 218, 201, 202, 203, 204, 205, 206,
    207, 208,
]; // 592 entries

#[cfg(not(feature = "no-optimized-legacy-encoding"))]
const BACKWARD_TABLE_UPPER: &'static [u16] = &[
    0, 0, 361, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 528, 64, 144, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 329, 417, 0, 0, 96, 0, 0, 0, 0,
    0, 0, 0, 226, 465, 290,
]; // 151 entries

/// Returns the index pointer for code point `code` in this index.
#[inline]
#[cfg(not(feature = "no-optimized-legacy-encoding"))]
pub fn backward(code: u32) -> u8 {
    let offset = (code >> 6) as usize;
    let offset = if offset < 151 {BACKWARD_TABLE_UPPER[offset] as usize} else {0};
    BACKWARD_TABLE_LOWER[offset + ((code & 63) as usize)]
}

/// Returns the index pointer for code point `code` in this index.
#[cfg(feature = "no-optimized-legacy-encoding")]
pub fn backward(code: u32) -> u8 {
    if code > 9632 || ((0x60005u32 >> (code >> 9)) & 1) == 0 { return 0; }
    let code = code as u16;
    for i in 0..0x80 {
        if FORWARD_TABLE[i as usize] == code { return 0x80 + i; }
    }
    0
}

#[cfg(test)]
single_byte_tests! {
}
