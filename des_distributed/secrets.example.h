// =============================================================================
// secrets.example.h — template for secrets.h
// =============================================================================
// Copy this file to secrets.h in the same folder and fill it in. secrets.h is
// listed in .gitignore and must never be committed; this template carries no
// real values and is safe to publish.
#pragma once

// Wi-Fi access point the nodes join.
#define WIFI_SSID "your-network"
#define WIFI_PASS "your-password"

// The cell's shared secret: every frame is signed with HMAC-SHA256 under it.
// IDENTICAL on every node of the cell, known to nothing else — whoever has it
// can speak for any node. At least 32 characters, random. Make one with:
//     python -c "import secrets; print(secrets.token_hex(32))"
// A compiler flag (-DDES_AUTH_KEY=...) takes precedence over this value.
// The placeholder is deliberately too short: the build refuses to start until
// it has been replaced by a real key.
#ifndef DES_AUTH_KEY
#define DES_AUTH_KEY "REPLACE-ME"
#endif
