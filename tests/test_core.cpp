// Lightweight unit tests – no external test framework required
#include "../include/entropy.hpp"
#include "../include/dna_identity.hpp"
#include "../include/aes_sea.hpp"
#include "../include/dual_mc.hpp"
#include "../include/p2pe_channel.hpp"
#include "../include/iam_registry.hpp"
#include "../include/bce_ledger.hpp"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace cyb3r;

static int passed = 0;
static int failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { ++passed; std::cout << "  PASS  " << msg << "\n"; } \
    else { ++failed; std::cout << "  FAIL  " << msg << "\n"; } \
} while(0)

void test_entropy_and_dna() {
    std::cout << "\n[TEST] Entropy + DNA\n";
    EntropySource src(0x1234);
    auto b1 = src.collect_256();
    auto b2 = src.collect_256();
    CHECK(b1 != b2, "two entropy samples differ");
    CHECK(src.health_ok(), "entropy health ok");

    auto dna = DNAFactory::create(src, "test-device");
    CHECK(dna.hex.size() == 64, "DNA hex length is 64");
    CHECK(!dna.short_id.empty(), "short_id present");
}

void test_aes_sea_and_key() {
    std::cout << "\n[TEST] AES-SEA key derivation + encrypt/decrypt\n";
    Bytes32 a{}, b{};
    for (int i = 0; i < 32; ++i) { a[i] = i; b[i] = 32 - i; }

    auto key512 = AES_SEA::derive_512(a, b);
    auto key512b = AES_SEA::derive_512(a, b);
    CHECK(key512 == key512b, "derive_512 is deterministic");

    auto sk = AES_SEA::session_key_from_512(key512, 42);
    std::string plain = "Cyb3rALIENS test payload";
    auto ct = AES_SEA::encrypt(sk, std::vector<uint8_t>(plain.begin(), plain.end()));
    auto pt = AES_SEA::decrypt(sk, ct);
    std::string recovered(pt.begin(), pt.end());
    CHECK(recovered == plain, "AES round-trip succeeds");
}

void test_dual_mc_handshake() {
    std::cout << "\n[TEST] Dual-MC handshake\n";
    DualMCPair pair(0xAA01, 0xBB02);
    pair.perform_handshake();
    CHECK(pair.master.is_ready() && pair.slave.is_ready(), "both MCs ready");
    auto k1 = pair.master.compute_validation_key();
    auto k2 = pair.slave.compute_validation_key();
    CHECK(k1 == k2, "Master and Slave produce identical 512-bit key");
    CHECK(k1 == pair.validation_key, "stored validation_key matches");
}

void test_p2pe_channel() {
    std::cout << "\n[TEST] P2PE channel\n";
    DualMCPair pair(0xCC03, 0xDD04);
    pair.perform_handshake();
    const auto& da = pair.master.dna();
    const auto& db = pair.slave.dna();

    P2PEChannel ab(da, db, pair.validation_key);
    P2PEChannel ba(db, da, pair.validation_key);

    std::string msg = "secure hello";
    auto ct = ab.send(std::vector<uint8_t>(msg.begin(), msg.end()));
    auto pt = ba.receive(ct);
    std::string rec(pt.begin(), pt.end());
    CHECK(rec == msg, "P2PE A→B message recovers correctly");
}

void test_iam_and_ledger() {
    std::cout << "\n[TEST] IAM + BCE Ledger\n";
    IAMRegistry iam;
    BCELedger ledger;

    EntropySource src(99);
    auto dna = DNAFactory::create(src, "unit-test");
    CHECK(iam.register_device(dna, "test"), "register succeeds");
    CHECK(!iam.register_device(dna, "dup"), "duplicate register fails");
    CHECK(iam.mark_active(dna), "mark active");
    CHECK(iam.count() == 1, "count == 1");

    ledger.append("REGISTER", dna);
    CHECK(ledger.size() >= 2, "ledger has genesis + register");
    CHECK(ledger.verify_integrity(), "ledger integrity holds");

    // Persistence round-trip
    CHECK(iam.save("/tmp/test_iam.txt"), "IAM save");
    CHECK(ledger.save("/tmp/test_ledger.txt"), "Ledger save");

    IAMRegistry iam2;
    BCELedger ledger2;
    CHECK(iam2.load("/tmp/test_iam.txt"), "IAM load");
    CHECK(ledger2.load("/tmp/test_ledger.txt"), "Ledger load");
    CHECK(iam2.count() == 1, "loaded IAM has 1 device");
    CHECK(ledger2.verify_integrity(), "loaded ledger integrity ok");
}

int main() {
    std::cout << "=== Cyb3rALIENS Unit Tests ===\n";
    test_entropy_and_dna();
    test_aes_sea_and_key();
    test_dual_mc_handshake();
    test_p2pe_channel();
    test_iam_and_ledger();

    std::cout << "\n================================\n";
    std::cout << "Passed: " << passed << "   Failed: " << failed << "\n";
    return failed == 0 ? 0 : 1;
}
