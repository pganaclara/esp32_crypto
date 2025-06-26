#include <Arduino.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <string.h>
#include <vector>
#include <map>
#include <string>

// Typedef for Ciphertext (a pair of ECP points)
typedef struct {
    mbedtls_ecp_point c1;
    mbedtls_ecp_point c2;
} Ciphertext;

Generic Automaton Configuration Struct
struct AutomatonConfig {
    int num_states;
    int num_events;
    std::vector<String> event_names;
    std::map<String, std::vector<std::pair<int, int>>> transitions;
    std::vector<std::vector<int>> requirements;
};

//Single Point of Configuration
void define_automaton(AutomatonConfig& config) {
    config.num_states = 6;
    config.num_events = 4;
    config.event_names = {"a1", "a2", "b1", "b2"};

    // B-Matrix transition rules: {from_state, to_state}
    config.transitions["a1"] = {{0, 1}, {5, 4}};
    config.transitions["a2"] = {{2, 5}};
    config.transitions["b1"] = {{4, 2}, {2, 4}};
    config.transitions["b2"] = {{4, 4}};

    // R-Matrix requirement rules
    config.requirements = {
        {1,0,0,0,0,1}, {0,0,1,0,0,0}, {0,1,0,0,1,0}, {0,0,1,0,1,1}
    };
}

// --- Global Variables & Contexts ---
AutomatonConfig active_automaton;
std::vector<std::vector<int>> R_MATRIX;
std::map<String, std::vector<std::vector<int>>> B_MATRICES;
std::map<String, int> EVENT_INDEX_MAP;

#define ELLIPTIC_CURVE MBEDTLS_ECP_DP_SECP256R1

mbedtls_ecp_group *grp_ptr;
mbedtls_ecp_point *G_ptr;
mbedtls_mpi *priv_key_ptr;
mbedtls_ecp_point *pub_key_ptr;
mbedtls_ctr_drbg_context *ctr_drbg_ptr;
mbedtls_entropy_context *entropy_ptr;

// --- Helper Functions (Cryptography & Homomorphic Operations) ---

int map_point_to_int(const mbedtls_ecp_point* p) {
    if (mbedtls_ecp_is_zero((mbedtls_ecp_point*)p)) {
        return 0;
    }
    // For this automaton, any non-zero point means the state is active (1)
    return 1;
}

int ec_elgamal_encrypt(int m, Ciphertext* ciphertext) {
    mbedtls_mpi r_mpi;
    mbedtls_ecp_point r_pub_key;
    int ret;

    mbedtls_mpi_init(&r_mpi);
    mbedtls_ecp_point_init(&r_pub_key);
    mbedtls_ecp_point_init(&ciphertext->c1);
    mbedtls_ecp_point_init(&ciphertext->c2);

    ret = mbedtls_ecp_gen_privkey(grp_ptr, &r_mpi, mbedtls_ctr_drbg_random, ctr_drbg_ptr);
    if (ret != 0) goto cleanup_encrypt;

    ret = mbedtls_ecp_mul(grp_ptr, &ciphertext->c1, &r_mpi, G_ptr, mbedtls_ctr_drbg_random, ctr_drbg_ptr);
    if (ret != 0) goto cleanup_encrypt;

    ret = mbedtls_ecp_mul(grp_ptr, &r_pub_key, &r_mpi, pub_key_ptr, mbedtls_ctr_drbg_random, ctr_drbg_ptr);
    if (ret != 0) goto cleanup_encrypt_rpub;

    if (m == 0) {
        mbedtls_ecp_copy(&ciphertext->c2, &r_pub_key);
    } else {
        mbedtls_ecp_point p_m;
        mbedtls_ecp_point_init(&p_m);
        mbedtls_mpi M_mpi;
        mbedtls_mpi_init(&M_mpi);
        mbedtls_mpi_lset(&M_mpi, m);
        ret = mbedtls_ecp_mul(grp_ptr, &p_m, &M_mpi, G_ptr, mbedtls_ctr_drbg_random, ctr_drbg_ptr);
        
        mbedtls_mpi one;
        mbedtls_mpi_init(&one);
        mbedtls_mpi_lset(&one, 1);
        ret = mbedtls_ecp_muladd(grp_ptr, &ciphertext->c2, &one, &p_m, &one, &r_pub_key);
        
        mbedtls_ecp_point_free(&p_m);
        mbedtls_mpi_free(&M_mpi);
        mbedtls_mpi_free(&one);
    }

cleanup_encrypt_rpub:
    mbedtls_ecp_point_free(&r_pub_key);
cleanup_encrypt:
    mbedtls_mpi_free(&r_mpi);
    return ret;
}

int ec_elgamal_decrypt(const Ciphertext* ciphertext, int* decrypted_m) {
    mbedtls_ecp_point s, neg_s, p_m;
    int ret;

    mbedtls_ecp_point_init(&s);
    mbedtls_ecp_point_init(&neg_s);
    mbedtls_ecp_point_init(&p_m);

    ret = mbedtls_ecp_mul(grp_ptr, &s, priv_key_ptr, &ciphertext->c1, mbedtls_ctr_drbg_random, ctr_drbg_ptr);
    if (ret != 0) goto cleanup;

    mbedtls_mpi neg_scalar;
    mbedtls_mpi_init(&neg_scalar);
    mbedtls_mpi_sub_int(&neg_scalar, &grp_ptr->N, 1);
    ret = mbedtls_ecp_mul(grp_ptr, &neg_s, &neg_scalar, &s, mbedtls_ctr_drbg_random, ctr_drbg_ptr);
    mbedtls_mpi_free(&neg_scalar);
    if(ret != 0) goto cleanup;
    
    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_lset(&one, 1);
    ret = mbedtls_ecp_muladd(grp_ptr, &p_m, &one, &ciphertext->c2, &one, &neg_s);
    mbedtls_mpi_free(&one);
    if (ret != 0) goto cleanup;

    *decrypted_m = map_point_to_int(&p_m);
    
cleanup:
    mbedtls_ecp_point_free(&s);
    mbedtls_ecp_point_free(&neg_s);
    mbedtls_ecp_point_free(&p_m);
    return ret;
}

int ec_elgamal_add(const Ciphertext* c_a, const Ciphertext* c_b, Ciphertext* result_c) {
    int ret;
    mbedtls_ecp_point_init(&result_c->c1);
    mbedtls_ecp_point_init(&result_c->c2);

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_lset(&one, 1);

    ret = mbedtls_ecp_muladd(grp_ptr, &result_c->c1, &one, &c_a->c1, &one, &c_b->c1);
    if (ret != 0) goto cleanup_one;

    ret = mbedtls_ecp_muladd(grp_ptr, &result_c->c2, &one, &c_a->c2, &one, &c_b->c2);

cleanup_one:
    mbedtls_mpi_free(&one);
    return ret;
}

void free_ciphertext_vector(std::vector<Ciphertext>& vec) {
    for (auto& c : vec) {
        mbedtls_ecp_point_free(&c.c1);
        mbedtls_ecp_point_free(&c.c2);
    }
    vec.clear();
}

int encrypt_values(const std::vector<int>& values, std::vector<Ciphertext>& ciphertext_list) {
    free_ciphertext_vector(ciphertext_list);
    ciphertext_list.reserve(values.size());
    for (int val : values) {
        Ciphertext c;
        int ret = ec_elgamal_encrypt(val, &c);
        if (ret != 0) { 
            mbedtls_ecp_point_free(&c.c1);
            mbedtls_ecp_point_free(&c.c2);
            return ret; 
        }
        ciphertext_list.push_back(c);
    }
    return 0;
}

int decrypt_values(const std::vector<Ciphertext>& ciphertext_list, std::vector<int>& decrypted_values) {
    decrypted_values.clear();
    decrypted_values.reserve(ciphertext_list.size());
    for (const Ciphertext& c : ciphertext_list) {
        int val;
        int ret = ec_elgamal_decrypt(&c, &val);
        if (ret != 0) return ret;
        decrypted_values.push_back(val);
    }
    return 0;
}

int sum_ciphertexts(const std::vector<Ciphertext>& ciphertext_list, Ciphertext* result_c) {
    if (ciphertext_list.empty()) {
        return ec_elgamal_encrypt(0, result_c);
    }

    Ciphertext accumulated;
    mbedtls_ecp_point_init(&accumulated.c1);
    mbedtls_ecp_point_init(&accumulated.c2);
    mbedtls_ecp_copy(&accumulated.c1, &ciphertext_list[0].c1);
    mbedtls_ecp_copy(&accumulated.c2, &ciphertext_list[0].c2);
    
    for (size_t i = 1; i < ciphertext_list.size(); ++i) {
        Ciphertext temp_result;
        int ret = ec_elgamal_add(&accumulated, &ciphertext_list[i], &temp_result);
        
        mbedtls_ecp_point_free(&accumulated.c1);
        mbedtls_ecp_point_free(&accumulated.c2);

        if (ret != 0) {
            mbedtls_ecp_point_free(&temp_result.c1);
            mbedtls_ecp_point_free(&temp_result.c2);
            return ret;
        }
        accumulated = temp_result;
    }
    *result_c = accumulated;
    return 0;
}

std::vector<int> event_to_vector(const String& event_name) {
    std::vector<int> event_vec(active_automaton.num_events, 0);
    if (EVENT_INDEX_MAP.count(event_name)) {
        event_vec[EVENT_INDEX_MAP[event_name]] = 1;
    }
    return event_vec;
}

int sum_row(const std::vector<Ciphertext>& encrypted_vector, const std::vector<int>& binary_row, Ciphertext* result_c) {
    std::vector<Ciphertext> selected_ciphers;
    for (size_t i = 0; i < binary_row.size(); ++i) {
        if (binary_row[i] == 1) {
            selected_ciphers.push_back(encrypted_vector[i]);
        }
    }
    return sum_ciphertexts(selected_ciphers, result_c);
}

int matvec(const std::vector<Ciphertext>& encrypted_vector, const std::vector<std::vector<int>>& binary_matrix, std::vector<Ciphertext>& result_list) {
    free_ciphertext_vector(result_list);
    result_list.reserve(binary_matrix.size());
    for (size_t j = 0; j < binary_matrix.size(); ++j) {
        Ciphertext temp_c;
        int ret = sum_row(encrypted_vector, binary_matrix[j], &temp_c);
        if (ret != 0) {
            mbedtls_ecp_point_free(&temp_c.c1);
            mbedtls_ecp_point_free(&temp_c.c2);
            return ret;
        }
        result_list.push_back(temp_c);
    }
    return 0;
}

int next_state(const std::vector<Ciphertext>& encrypted_state, const std::vector<int>& cleartext_event, std::vector<Ciphertext>& new_encrypted_state) {
    free_ciphertext_vector(new_encrypted_state);
    new_encrypted_state.reserve(active_automaton.num_states);
    std::vector<Ciphertext> accumulated_contributions;
    for (int i = 0; i < active_automaton.num_states; ++i) {
        Ciphertext initial_zero;
        int ret = ec_elgamal_encrypt(0, &initial_zero);
        if (ret != 0) return ret;
        accumulated_contributions.push_back(initial_zero);
    }
    for (const auto& pair : EVENT_INDEX_MAP) {
        const String& event_name = pair.first;
        int event_idx = pair.second;
        if (cleartext_event[event_idx] == 1) {
            const auto& b_matrix = B_MATRICES.at(event_name);
            std::vector<Ciphertext> contribution;
            int ret = matvec(encrypted_state, b_matrix, contribution);
            if (ret != 0) { free_ciphertext_vector(contribution); free_ciphertext_vector(accumulated_contributions); return ret; }
            for (int i = 0; i < active_automaton.num_states; ++i) {
                Ciphertext temp_sum;
                ret = ec_elgamal_add(&accumulated_contributions[i], &contribution[i], &temp_sum);
                mbedtls_ecp_point_free(&accumulated_contributions[i].c1);
                mbedtls_ecp_point_free(&accumulated_contributions[i].c2);
                if (ret != 0) { free_ciphertext_vector(contribution); free_ciphertext_vector(accumulated_contributions); return ret; }
                accumulated_contributions[i] = temp_sum;
            }
            free_ciphertext_vector(contribution);
        }
    }
    new_encrypted_state = accumulated_contributions;
    return 0;
}

int get_enabled_events(const std::vector<Ciphertext>& encrypted_state, std::vector<Ciphertext>& enabled_ciphertexts) {
    return matvec(encrypted_state, R_MATRIX, enabled_ciphertexts);
}


// --- Clear-Text Calculation Functions for Comparison ---
std::vector<int> next_state_cleartext(const std::vector<int>& current_state, const String& event_name) {
    std::vector<int> new_state(active_automaton.num_states, 0);
    if (B_MATRICES.count(event_name) == 0) {
        return new_state;
    }
    const auto& b_matrix = B_MATRICES.at(event_name);

    for (int i = 0; i < active_automaton.num_states; ++i) {
        int sum = 0;
        for (int j = 0; j < active_automaton.num_states; ++j) {
            sum += b_matrix[i][j] * current_state[j];
        }
        if (sum > 0) {
            new_state[i] = 1;
        }
    }
    return new_state;
}

std::vector<int> get_enabled_events_cleartext(const std::vector<int>& current_state) {
    std::vector<int> enabled_events(active_automaton.num_events, 0);
    for (int i = 0; i < active_automaton.num_events; ++i) {
        int sum = 0;
        for (int j = 0; j < active_automaton.num_states; ++j) {
            sum += R_MATRIX[i][j] * current_state[j];
        }
        if (sum > 0) {
            enabled_events[i] = 1;
        }
    }
    return enabled_events;
}


// --- Arduino Setup and Loop ---
void setup() {
    Serial.begin(115200);
    delay(100); 

    Serial.println("--- Starting Generic Automaton Simulation with Comparison ---");
    define_automaton(active_automaton);
    Serial.println("Automaton definition loaded.");

    R_MATRIX = active_automaton.requirements;
    for (const auto& event_name : active_automaton.event_names) {
        std::vector<std::vector<int>> b_matrix(active_automaton.num_states, std::vector<int>(active_automaton.num_states, 0));
        if (active_automaton.transitions.count(event_name)) {
            for (const auto& t : active_automaton.transitions.at(event_name)) {
                b_matrix[t.second][t.first] = 1;
            }
        }
        B_MATRICES[event_name] = b_matrix;
    }
    for (size_t i = 0; i < active_automaton.event_names.size(); ++i) {
        EVENT_INDEX_MAP[active_automaton.event_names[i]] = i;
    }
    Serial.println("Live matrices generated from definition.");

    grp_ptr = new mbedtls_ecp_group(); mbedtls_ecp_group_init(grp_ptr);
    G_ptr = new mbedtls_ecp_point(); mbedtls_ecp_point_init(G_ptr);
    priv_key_ptr = new mbedtls_mpi(); mbedtls_mpi_init(priv_key_ptr);
    pub_key_ptr = new mbedtls_ecp_point(); mbedtls_ecp_point_init(pub_key_ptr);
    ctr_drbg_ptr = new mbedtls_ctr_drbg_context(); mbedtls_ctr_drbg_init(ctr_drbg_ptr);
    entropy_ptr = new mbedtls_entropy_context(); mbedtls_entropy_init(entropy_ptr);
    int ret;
    const char *pers = "elgamal_automaton";
    ret = mbedtls_ctr_drbg_seed(ctr_drbg_ptr, mbedtls_entropy_func, entropy_ptr, (const unsigned char *)pers, strlen(pers));
    ret = mbedtls_ecp_group_load(grp_ptr, ELLIPTIC_CURVE);
    mbedtls_ecp_copy(G_ptr, &grp_ptr->G);
    ret = mbedtls_ecp_gen_keypair(grp_ptr, priv_key_ptr, pub_key_ptr, mbedtls_ctr_drbg_random, ctr_drbg_ptr);
    if (ret != 0) { Serial.printf("Crypto init failed: -0x%04X\n", -ret); return; }
    Serial.println("Cryptography engine initialized successfully.");

    Serial.println("\n--- Starting Simulation ---");
    
    std::vector<int> initial_cleartext_state = {1, 0, 0, 0, 0, 0};
    std::vector<int> current_cleartext_state = initial_cleartext_state;
    std::vector<Ciphertext> encrypted_state;
    encrypt_values(initial_cleartext_state, encrypted_state);

    std::vector<String> event_sequence = {"a1", "b1", "a2", "b2"};
    bool overall_match = true;

    for (int step = 0; step < event_sequence.size(); ++step) {
        String event_name = event_sequence[step];
        std::vector<int> cleartext_event_vector = event_to_vector(event_name);

        Serial.printf("\n--- Step %d (Event: %s) ---\n", step + 1, event_name.c_str());

        // 1. Homomorphic Calculation
        std::vector<Ciphertext> new_encrypted_state;
        next_state(encrypted_state, cleartext_event_vector, new_encrypted_state);
        std::vector<Ciphertext> enabled_ciphertexts;
        get_enabled_events(new_encrypted_state, enabled_ciphertexts);
        
        std::vector<int> decrypted_state, decrypted_enabled_events;
        decrypt_values(new_encrypted_state, decrypted_state);
        decrypt_values(enabled_ciphertexts, decrypted_enabled_events);

        // 2. Clear-Text Calculation
        std::vector<int> next_clear_state = next_state_cleartext(current_cleartext_state, event_name);
        std::vector<int> enabled_clear_events = get_enabled_events_cleartext(next_clear_state);
        
        // 3. Print and Compare
        Serial.print("Homomorphic Result -> New State: [");
        for(size_t i=0; i<decrypted_state.size(); ++i) { Serial.printf("%d%s", decrypted_state[i], i == decrypted_state.size()-1 ? "" : ", "); }
        Serial.print("], Enabled: [");
        for(size_t i=0; i<decrypted_enabled_events.size(); ++i) { Serial.printf("%d%s", decrypted_enabled_events[i], i == decrypted_enabled_events.size()-1 ? "" : ", "); }
        Serial.println("]");
        
        Serial.print("Clear-Text Result  -> New State: [");
        for(size_t i=0; i<next_clear_state.size(); ++i) { Serial.printf("%d%s", next_clear_state[i], i == next_clear_state.size()-1 ? "" : ", "); }
        Serial.print("], Enabled: [");
        for(size_t i=0; i<enabled_clear_events.size(); ++i) { Serial.printf("%d%s", enabled_clear_events[i], i == enabled_clear_events.size()-1 ? "" : ", "); }
        Serial.println("]");

        if (decrypted_state != next_clear_state || decrypted_enabled_events != enabled_clear_events) {
            Serial.println(">>> MISMATCH DETECTED! <<<");
            overall_match = false;
        } else {
            Serial.println(">>> Results Match! <<<");
        }

        current_cleartext_state = next_clear_state;
        free_ciphertext_vector(encrypted_state);
        encrypted_state = new_encrypted_state;
        free_ciphertext_vector(enabled_ciphertexts);
    }
    
    Serial.println("\n--- Simulation Finished ---");
    if(overall_match) {
        Serial.println(">>> OVERALL RESULT: All steps matched successfully! <<<");
    } else {
        Serial.println(">>> OVERALL RESULT: One or more steps had a mismatch. <<<");
    }
    
    // Cleanup
    free_ciphertext_vector(encrypted_state);
    mbedtls_ecp_group_free(grp_ptr); delete grp_ptr;
    mbedtls_ecp_point_free(G_ptr); delete G_ptr;
    mbedtls_mpi_free(priv_key_ptr); delete priv_key_ptr;
    mbedtls_ecp_point_free(pub_key_ptr); delete pub_key_ptr;
    mbedtls_ctr_drbg_free(ctr_drbg_ptr); delete ctr_drbg_ptr;
    mbedtls_entropy_free(entropy_ptr); delete entropy_ptr;
}

void loop() {
    delay(5000);
}