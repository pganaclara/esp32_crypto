// =============================================================================
// secrets.example.h — template for des_split's secrets.h
// =============================================================================
// Copy this file to secrets.h in the same folder and fill it in. secrets.h is
// listed in .gitignore and must never be committed; this template carries no
// real values and is safe to publish.
#pragma once

// Wi-Fi access point the two boards join.
#define WIFI_SSID "your-network"
#define WIFI_PASS "your-password"

// One identity key per board, on the curve of DES_CURVE (des_split.ino). Make
// them with
//     python make_keys.py 256 >> secrets.h
// and run it again if DES_CURVE changes. Each board compiles in only its own
// private key (DES_ID_...) and both public keys (DES_PUB_...): a copy of one
// board's flash does not let anyone pass for the other board.
