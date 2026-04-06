// =============================================================================
// homomorphic-esp32-modular_auto.ino 
//
// DES synthesis + EC-ElGamal homomorphic benchmark on ESP32.
//
// APPROACHES
// ──────────
//   MONOLITHIC    — Sup(P1‖…‖Pk, E1‖…‖Em). If synthesis exceeds
//                   MONO_STATE_LIMIT, HE is skipped and theoretical cost
//                   is estimated from the partial state count.
//
//   LOCAL MODULAR — one supervisor per spec: Sj = Sup(Pj_local, Ej),
//                   where Pj_local = plants sharing ≥1 event with Ej.
//                   Nonconflict of {Sj} verified offline (not here).
//
// ORACLE (cleartext, never timed)
// ────────────────────────────────
//   ONE reference per step, printed as [Oracle].
//   Uses monolithic cleartext when monolithic synthesis succeeded;
//   local modular cleartext otherwise.
//   Both Mono and LMod results are validated against this single reference.
//
// KEY OPTIMISATIONS
// ──────────────────
//   1. Sparse B matrices: DFA transitions are partial permutations → O(n) RAM,
//      homomorphic transition = point copies only (zero EC additions).
//   2. R_local pruning: rows where ALL states have R[li][s]=1 are removed.
//      An event that is never disabled by this supervisor need not be decrypted.
//      Reduces decryptions to only events the supervisor can actually constrain.
//   3. Cache: when ev ∉ alphabet(Sj), state unchanged → reuse cached enabled bits.
//      Zero crypto cost for that supervisor on that step.
//   4. ENC_THRESHOLD: supervisors with more than ENC_THRESHOLD states fall back
//      to cleartext (noted in output). For FMS: E5,E6,E7 are cleartext.
//
// HOW TO USE: set ACTIVE_PROBLEM in SECTION 6.
// =============================================================================

#include <Arduino.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <string.h>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <algorithm>

// Synthesis limit: raised to 500 so FMS monolithic synthesis can complete
// and we get the exact state count. HE is only run if the encrypted state
// vector fits in heap (states × ~400 bytes < HE_MEMORY_LIMIT).
#define MONO_STATE_LIMIT    500
#define HE_MEMORY_LIMIT   (180*1024)  // bytes: leave room for LMod + crypto ctx
#define ENC_THRESHOLD      32   // supervisors with more states run cleartext

// =============================================================================
// SECTION 1 — TYPE DEFINITIONS
// =============================================================================

using StateId    = int;
using EventLabel = String;

struct Transition { StateId from; EventLabel event; StateId to; };

struct DFA {
    String     name;
    int        num_states;
    StateId    initial;
    std::vector<bool>       marked;
    std::vector<Transition> transitions;
    std::map<StateId, std::map<EventLabel, StateId>> delta;
    void build_delta() {
        delta.clear();
        for (auto& t : transitions) delta[t.from][t.event] = t.to;
    }
};

struct ProductState {
    std::vector<StateId> components;
    bool operator<(const ProductState& o)  const { return components <  o.components; }
    bool operator==(const ProductState& o) const { return components == o.components; }
};

struct ProductDFA {
    std::vector<ProductState>              states;
    std::map<ProductState, int>            state_index;
    int                                    initial;
    std::vector<bool>                      marked;
    std::vector<std::map<EventLabel, int>> delta;
    std::vector<EventLabel>                alphabet;
    bool                                   aborted;
};

struct AutomatonConfig {
    int                  num_states;
    int                  num_events;
    std::vector<String>  event_names;
    std::map<String, std::vector<std::pair<int,int>>> transitions;
    std::vector<std::vector<int>> requirements;
    std::vector<int>     initial_state;
    std::vector<String>  simulation_sequence;
};

using SparseTrans = std::vector<std::pair<int,int>>;  // (to, from)

struct ModSupervisor {
    String           name;
    int              num_states;
    std::vector<int> initial_state;
    std::set<String> own_events;
    bool             encrypted;          // false → cleartext fallback

    // Sparse B: (to,from) pairs per own event. O(n) RAM.
    std::map<String, SparseTrans> B_sparse;

    // R_local[li][s]: enablement rows for constraining events only.
    // Rows where ALL entries are 1 are pruned (supervisor never disables that event).
    std::vector<std::vector<int>> R_local;
    std::vector<int>              own_event_indices;  // local row → global ev idx

    // Homomorphic cache
    std::vector<int> cached_en;
    bool             cache_valid;

    int num_global_events;
};

typedef struct { 
    mbedtls_ecp_point c1; 
    mbedtls_ecp_point c2; 
} Ciphertext;

// Completely separate oracle state — never shares memory with HE paths.
struct OracleState {
    std::vector<std::vector<int>> st;  // st[sup_idx][state_idx]

    void init(const std::vector<ModSupervisor>& sups) {
        st.resize(sups.size());
        for (size_t i = 0; i < sups.size(); ++i) st[i] = sups[i].initial_state;
    }

    std::vector<int> step(const std::vector<ModSupervisor>& sups,
                           const String& ev, int num_global_ev) {
        std::vector<int> en(num_global_ev, 1);
        for (size_t i = 0; i < sups.size(); ++i) {
            const ModSupervisor& ms = sups[i];
            // Advance state
            if (ms.own_events.count(ev) && ms.B_sparse.count(ev)) {
                const SparseTrans& sp = ms.B_sparse.at(ev);
                std::vector<int> nxt(ms.num_states, 0);
                for (auto& pr : sp) nxt[pr.first] = st[i][pr.second];
                st[i] = nxt;
            }
            // Compute enabled from ALL own events (not just pruned R_local),
            // using the full sparse B structure to determine which transitions exist.
            // We use R_local for the constrained events and assume 1 for pruned ones.
            for (size_t li = 0; li < ms.own_event_indices.size(); ++li) {
                int gi = ms.own_event_indices[li];
                int e = 0;
                for (int s = 0; s < ms.num_states; ++s)
                    if (ms.R_local[li][s] && st[i][s]) { e = 1; break; }
                if (!e) en[gi] = 0;
            }
        }
        return en;
    }
};

// =============================================================================
// SECTION 2 — GLOBAL STATE
// =============================================================================

AutomatonConfig active_automaton;
bool            mono_he_runnable = false;  // true only if states fit in heap
int             mono_state_count = 0;      // exact synthesised state count
long            measured_muladd_us = 0;    // measured on device at startup
long            measured_scalar_mul_us_g = 80000; // scalar_mul cost (us), default 80ms

std::vector<ModSupervisor>           lmod_supervisors;
std::vector<std::vector<Ciphertext>> enc_lmod_states;
std::vector<std::vector<int>>        clr_lmod_exec;   // cleartext states for CLR sups

std::vector<std::vector<int>>                   R_MATRIX;
std::map<String, std::vector<std::vector<int>>> B_MATRICES_DENSE;
std::map<String, int>                           EVENT_INDEX_MAP;
std::vector<Ciphertext>                         enc_mono;

std::vector<String> global_event_names;

#define ELLIPTIC_CURVE MBEDTLS_ECP_DP_SECP256R1
mbedtls_ecp_group        *grp_ptr;
mbedtls_ecp_point        *G_ptr;
mbedtls_mpi              *priv_key_ptr;
mbedtls_ecp_point        *pub_key_ptr;
mbedtls_ctr_drbg_context *ctr_drbg_ptr;
mbedtls_entropy_context  *entropy_ptr;
mbedtls_mpi               g_one;
Ciphertext g_enc_zero;
bool       g_enc_zero_ready = false;

// =============================================================================
// SECTION 3 — DES SYNTHESIS ENGINE
// =============================================================================

static std::set<EventLabel> collect_alphabet(const std::vector<DFA>& dfas) {
    std::set<EventLabel> alpha;
    for (auto& d : dfas) for (auto& t : d.transitions) alpha.insert(t.event);
    return alpha;
}

static ProductDFA synchronous_product(const std::vector<DFA>& dfas,
                                       int state_limit = INT32_MAX) {
    std::set<EventLabel> alpha_set = collect_alphabet(dfas);
    std::vector<EventLabel> alphabet(alpha_set.begin(), alpha_set.end());
    int n = dfas.size();
    ProductDFA prod; prod.alphabet=alphabet; prod.initial=0; prod.aborted=false;

    ProductState init_ps;
    for (auto& d : dfas) init_ps.components.push_back(d.initial);
    auto is_marked = [&](const ProductState& ps) {
        for (int i=0;i<n;++i) if(!dfas[i].marked[ps.components[i]]) return false;
        return true;
    };
    prod.states.push_back(init_ps);
    prod.state_index[init_ps]=0;
    prod.marked.push_back(is_marked(init_ps));
    prod.delta.push_back({});

    size_t head=0;
    while (head < prod.states.size()) {
        if ((int)prod.states.size() > state_limit) {
            prod.aborted=true; return prod;
        }
        const ProductState cur = prod.states[head];
        int cur_idx=(int)head++;
        for (auto& ev : alphabet) {
            ProductState next_ps; next_ps.components.resize(n);
            bool feasible=true;
            for (int i=0;i<n;++i) {
                bool ev_in=false;
                for (auto& t:dfas[i].transitions) if(t.event==ev){ev_in=true;break;}
                if (ev_in){
                    auto sit=dfas[i].delta.find(cur.components[i]);
                    if(sit==dfas[i].delta.end()||!sit->second.count(ev))
                        {feasible=false;break;}
                    next_ps.components[i]=sit->second.at(ev);
                } else {
                    next_ps.components[i]=cur.components[i];
                }
            }
            if(!feasible) continue;
            if(!prod.state_index.count(next_ps)){
                int ni=prod.states.size();
                prod.state_index[next_ps]=ni;
                prod.states.push_back(next_ps);
                prod.marked.push_back(is_marked(next_ps));
                prod.delta.push_back({});
            }
            prod.delta[cur_idx][ev]=prod.state_index.at(next_ps);
        }
    }
    return prod;
}

static std::vector<bool> coreachable_states(const ProductDFA& prod) {
    int N=prod.states.size();
    std::vector<std::vector<int>> rev(N);
    for (int s=0;s<N;++s) for (auto& kv:prod.delta[s]) rev[kv.second].push_back(s);
    std::vector<bool> vis(N,false); std::vector<int> stk;
    for (int s=0;s<N;++s) if(prod.marked[s]){stk.push_back(s);vis[s]=true;}
    while (!stk.empty()){int c=stk.back();stk.pop_back();
        for (int p:rev[c]) if(!vis[p]){vis[p]=true;stk.push_back(p);}}
    return vis;
}

static std::vector<int> compact_indices(const ProductDFA& prod,
                                         const std::vector<bool>& keep) {
    int N=prod.states.size();
    std::vector<bool> reach(N,false);
    {std::vector<int> stk={prod.initial}; reach[prod.initial]=true;
     while (!stk.empty()){int s=stk.back();stk.pop_back();
         for (auto& kv:prod.delta[s])
             if(keep[kv.second]&&!reach[kv.second])
                 {reach[kv.second]=true;stk.push_back(kv.second);}}}
    std::vector<int> nidx(N,-1);
    {std::vector<bool> vis(N,false); std::vector<int> order,stk={prod.initial};
     vis[prod.initial]=true;
     while (!stk.empty()){int s=stk.back();stk.pop_back();
         if(keep[s]&&reach[s]) order.push_back(s);
         for (auto& kv:prod.delta[s])
             if(!vis[kv.second]){vis[kv.second]=true;stk.push_back(kv.second);}}
     int cnt=0; for (int s:order) nidx[s]=cnt++;}
    return nidx;
}

static AutomatonConfig supervisor_to_config(const ProductDFA& prod,
                                            const std::vector<bool>& keep,
                                            const std::vector<EventLabel>& all_ev,
                                            const std::vector<String>& sim_seq) {
    auto nidx=compact_indices(prod,keep);
    int N=prod.states.size();
    int count=0; for (int v:nidx) if(v+1>count) count=v+1;
    AutomatonConfig cfg;
    cfg.num_states=count; cfg.num_events=all_ev.size();
    cfg.event_names=all_ev; cfg.simulation_sequence=sim_seq;
    cfg.initial_state.assign(count,0);
    if(nidx[prod.initial]>=0) cfg.initial_state[nidx[prod.initial]]=1;
    for (int s=0;s<N;++s){
        if(nidx[s]<0) continue;
        for (auto& kv:prod.delta[s]){int t=kv.second;if(nidx[t]<0)continue;
            cfg.transitions[kv.first].push_back({nidx[s],nidx[t]});}}
    cfg.requirements.assign(cfg.num_events,std::vector<int>(count,0));
    for (int ei=0;ei<cfg.num_events;++ei){
        const String& ev=cfg.event_names[ei];
        if(cfg.transitions.count(ev))
            for (auto& pr:cfg.transitions.at(ev))
                cfg.requirements[ei][pr.first]=1;}
    return cfg;
}

static ModSupervisor product_to_mod_supervisor(
        const String& name, const ProductDFA& prod,
        const std::vector<bool>& keep,
        const std::vector<EventLabel>& global_events) {
    auto nidx=compact_indices(prod,keep);
    int N=prod.states.size();
    int count=0; for (int v:nidx) if(v+1>count) count=v+1;

    ModSupervisor ms;
    ms.name=name; ms.num_states=count;
    ms.num_global_events=global_events.size();
    ms.cache_valid=false;
    ms.encrypted=(count <= ENC_THRESHOLD);
    ms.initial_state.assign(count,0);
    if(nidx[prod.initial]>=0) ms.initial_state[nidx[prod.initial]]=1;

    std::map<String,std::vector<std::pair<int,int>>> tr;
    for (int s=0;s<N;++s){
        if(nidx[s]<0) continue;
        for (auto& kv:prod.delta[s]){int t=kv.second;if(nidx[t]<0)continue;
            tr[kv.first].push_back({nidx[s],nidx[t]});
            ms.own_events.insert(kv.first);}}

    for (auto& ev:ms.own_events){
        SparseTrans sp;
        for (auto& pr:tr.at(ev)) sp.push_back({pr.second,pr.first}); // (to,from)
        ms.B_sparse[ev]=sp;
    }

    // Build R_local, then PRUNE rows that are all-ones.
    // An all-one row means this event is enabled in every reachable state of this
    // supervisor → it can never be disabled → no need to decrypt it.
    ms.R_local.clear(); ms.own_event_indices.clear();
    for (size_t ei=0;ei<global_events.size();++ei){
        const String& ev=global_events[ei];
        if(!ms.own_events.count(ev)) continue;
        std::vector<int> row(count,0);
        if(tr.count(ev)) for (auto& pr:tr.at(ev)) row[pr.first]=1;
        // Prune: if all entries are 1, this supervisor never disables this event
        bool all_one=true;
        for (int s=0;s<count;++s) if(!row[s]){all_one=false;break;}
        if(all_one) continue;  // skip — contributes 1 to intersection always
        ms.R_local.push_back(row);
        ms.own_event_indices.push_back((int)ei);
    }
    ms.cached_en.assign(ms.own_event_indices.size(),1);
    return ms;
}

std::vector<DFA>    define_plants();
std::vector<DFA>    define_specs();
std::vector<String> define_simulation_sequence();

static void synthesise_automaton() {
    std::vector<DFA> plants=define_plants();
    std::vector<DFA> specs=define_specs();
    std::vector<DFA> all_dfas;
    for (auto& p:plants) all_dfas.push_back(p);
    for (auto& s:specs)  all_dfas.push_back(s);
    std::set<EventLabel> evset=collect_alphabet(all_dfas);
    global_event_names.assign(evset.begin(),evset.end());

    // ── Monolithic ────────────────────────────────────────────────────────────
    // Always synthesise fully (limit raised to 500) to get the exact state count.
    // HE is run only if the encrypted state vector fits in heap.
    Serial.println("[Synthesis] Monolithic...");
    mono_he_runnable=false; mono_state_count=0;
    {
        ProductDFA prod=synchronous_product(all_dfas, MONO_STATE_LIMIT);
        if(!prod.aborted){
            auto keep=coreachable_states(prod);
            active_automaton=supervisor_to_config(prod,keep,global_event_names,
                                                  define_simulation_sequence());
            mono_state_count=active_automaton.num_states;
            // HE is feasible only if encrypted state vector fits in heap
            int enc_state_bytes = mono_state_count * 400; // ~400 bytes per Ciphertext
            if(enc_state_bytes <= HE_MEMORY_LIMIT){
                mono_he_runnable=true;
                Serial.printf("[Synthesis] Monolithic: %d states, %d events [HE OK]\n",
                              active_automaton.num_states,active_automaton.num_events);
            } else {
                Serial.printf("[Synthesis] Monolithic: %d states, %d events"
                              " [HE SKIPPED - enc_state ~%dKB > %dKB limit]\n",
                              active_automaton.num_states,active_automaton.num_events,
                              enc_state_bytes/1024, HE_MEMORY_LIMIT/1024);
            }
        } else {
            // Synthesis hit the limit — raise MONO_STATE_LIMIT if this happens
            mono_state_count=prod.states.size();
            active_automaton.num_events=global_event_names.size();
            active_automaton.event_names=global_event_names;
            active_automaton.simulation_sequence=define_simulation_sequence();
            Serial.printf("[Synthesis] Monolithic: >%d states — raise MONO_STATE_LIMIT\n",
                          MONO_STATE_LIMIT);
        }
    }

    // ── Local Modular ─────────────────────────────────────────────────────────
    Serial.println("[Synthesis] Local Modular...");
    lmod_supervisors.clear();
    for (auto& spec:specs){
        std::set<EventLabel> spec_evs;
        for (auto& t:spec.transitions) spec_evs.insert(t.event);
        std::vector<DFA> combo;
        for (auto& p:plants){
            bool shares=false;
            for (auto& t:p.transitions) if(spec_evs.count(t.event)){shares=true;break;}
            if(shares) combo.push_back(p);
        }
        combo.push_back(spec);
        ProductDFA prod=synchronous_product(combo);
        auto keep=coreachable_states(prod);
        ModSupervisor ms=product_to_mod_supervisor(spec.name,prod,keep,
                                                    global_event_names);
        int pruned=(int)ms.own_events.size()-(int)ms.own_event_indices.size();
        Serial.printf("[Synthesis] LMod %-6s: %3d states, %2d own ev,"
                      " %2d constraining ev (pruned %d) [%s]\n",
                      ms.name.c_str(),ms.num_states,(int)ms.own_events.size(),
                      (int)ms.own_event_indices.size(),pruned,
                      ms.encrypted?"ENC":"CLR");
        lmod_supervisors.push_back(ms);
    }
    Serial.println("[Synthesis] Done.\n");
}

// =============================================================================
// SECTION 4 — CRYPTO PRIMITIVES
// =============================================================================

static int map_point_to_int(const mbedtls_ecp_point* p){
    return mbedtls_ecp_is_zero((mbedtls_ecp_point*)p)?0:1;}
static int ecp_point_add(mbedtls_ecp_group* grp,mbedtls_ecp_point* R,
                          const mbedtls_ecp_point* P,const mbedtls_ecp_point* Q){
    return mbedtls_ecp_muladd(grp,R,&g_one,P,&g_one,Q);}
static int ec_elgamal_encrypt(int m,Ciphertext* ct){
    mbedtls_mpi r;mbedtls_ecp_point rp;int ret;
    mbedtls_mpi_init(&r);mbedtls_ecp_point_init(&rp);
    mbedtls_ecp_point_init(&ct->c1);mbedtls_ecp_point_init(&ct->c2);
    ret=mbedtls_ecp_gen_privkey(grp_ptr,&r,mbedtls_ctr_drbg_random,ctr_drbg_ptr);
    if(ret) goto cl;
    ret=mbedtls_ecp_mul(grp_ptr,&ct->c1,&r,G_ptr,mbedtls_ctr_drbg_random,ctr_drbg_ptr);
    if(ret) goto cl;
    ret=mbedtls_ecp_mul(grp_ptr,&rp,&r,pub_key_ptr,mbedtls_ctr_drbg_random,ctr_drbg_ptr);
    if(ret) goto cl;
    if(m==0){mbedtls_ecp_copy(&ct->c2,&rp);}
    else{mbedtls_ecp_point pm;mbedtls_mpi mm;
        mbedtls_ecp_point_init(&pm);mbedtls_mpi_init(&mm);
        mbedtls_mpi_lset(&mm,m);
        ret=mbedtls_ecp_mul(grp_ptr,&pm,&mm,G_ptr,mbedtls_ctr_drbg_random,ctr_drbg_ptr);
        if(ret==0) ret=ecp_point_add(grp_ptr,&ct->c2,&pm,&rp);
        mbedtls_ecp_point_free(&pm);mbedtls_mpi_free(&mm);}
cl: mbedtls_ecp_point_free(&rp);mbedtls_mpi_free(&r);return ret;}
static int ec_elgamal_decrypt(const Ciphertext* ct,int* out){
    mbedtls_ecp_point ns,pm;mbedtls_mpi np;int ret;
    mbedtls_ecp_point_init(&ns);mbedtls_ecp_point_init(&pm);mbedtls_mpi_init(&np);
    ret=mbedtls_mpi_sub_mpi(&np,&grp_ptr->N,priv_key_ptr);if(ret) goto cl;
    ret=mbedtls_ecp_mul(grp_ptr,&ns,&np,&ct->c1,mbedtls_ctr_drbg_random,ctr_drbg_ptr);
    if(ret) goto cl;
    ret=ecp_point_add(grp_ptr,&pm,&ct->c2,&ns);if(ret) goto cl;
    *out=map_point_to_int(&pm);
cl: mbedtls_ecp_point_free(&ns);mbedtls_ecp_point_free(&pm);mbedtls_mpi_free(&np);
    return ret;}
static int ec_elgamal_add(const Ciphertext* a,const Ciphertext* b,Ciphertext* out){
    mbedtls_ecp_point_init(&out->c1);mbedtls_ecp_point_init(&out->c2);
    int ret=ecp_point_add(grp_ptr,&out->c1,&a->c1,&b->c1);
    if(ret==0) ret=ecp_point_add(grp_ptr,&out->c2,&a->c2,&b->c2);return ret;}
static void free_ct_vec(std::vector<Ciphertext>& v){
    for (auto& c:v){mbedtls_ecp_point_free(&c.c1);mbedtls_ecp_point_free(&c.c2);}
    v.clear();}
static int copy_enc_zero(Ciphertext* out){
    mbedtls_ecp_point_init(&out->c1);mbedtls_ecp_point_init(&out->c2);
    mbedtls_ecp_copy(&out->c1,&g_enc_zero.c1);
    mbedtls_ecp_copy(&out->c2,&g_enc_zero.c2);return 0;}
static int encrypt_values(const std::vector<int>& vals,std::vector<Ciphertext>& out){
    free_ct_vec(out);out.reserve(vals.size());
    for (int v:vals){Ciphertext c;int ret=ec_elgamal_encrypt(v,&c);
        if(ret){mbedtls_ecp_point_free(&c.c1);mbedtls_ecp_point_free(&c.c2);return ret;}
        out.push_back(c);}return 0;}
static int decrypt_values(const std::vector<Ciphertext>& in,std::vector<int>& out){
    out.clear();out.reserve(in.size());
    for (size_t i=0;i<in.size();++i){int v;int ret=ec_elgamal_decrypt(&in[i],&v);
        if(ret){Serial.printf("[dec] ERR %d: -0x%04X\n",(int)i,-ret);return ret;}
        out.push_back(v);}return 0;}

// =============================================================================
// SECTION 5 — HOMOMORPHIC OPERATORS
// =============================================================================

static int sum_row(const std::vector<Ciphertext>& enc,
                   const std::vector<int>& row,Ciphertext* out){
    int first=-1,cnt=0;
    for (size_t i=0;i<row.size();++i) if(row[i]==1){if(first<0)first=(int)i;cnt++;}
    if(cnt==0) return copy_enc_zero(out);
    mbedtls_ecp_point_init(&out->c1);mbedtls_ecp_point_init(&out->c2);
    mbedtls_ecp_copy(&out->c1,&enc[first].c1);
    mbedtls_ecp_copy(&out->c2,&enc[first].c2);
    if(cnt==1) return 0;
    bool past=false;
    for (size_t i=0;i<row.size();++i){
        if(row[i]!=1) continue;
        if(!past){past=true;continue;}
        Ciphertext tmp;int ret=ec_elgamal_add(out,&enc[i],&tmp);
        mbedtls_ecp_point_free(&out->c1);mbedtls_ecp_point_free(&out->c2);
        if(ret){mbedtls_ecp_point_free(&tmp.c1);mbedtls_ecp_point_free(&tmp.c2);return ret;}
        *out=tmp;}
    return 0;}

static int matvec_dense(const std::vector<Ciphertext>& enc,
                         const std::vector<std::vector<int>>& mat,
                         std::vector<Ciphertext>& out){
    free_ct_vec(out);out.reserve(mat.size());
    for (auto& row:mat){Ciphertext tmp;int ret=sum_row(enc,row,&tmp);
        if(ret){mbedtls_ecp_point_free(&tmp.c1);mbedtls_ecp_point_free(&tmp.c2);return ret;}
        out.push_back(tmp);}return 0;}

// Sparse transition: enc_next[to] = enc_state[from], rest = E(0). Zero EC adds.
static int sparse_transition(const std::vector<Ciphertext>& enc_state,
                              const SparseTrans& sp,int n,
                              std::vector<Ciphertext>& enc_next){
    free_ct_vec(enc_next);enc_next.resize(n);
    std::vector<bool> filled(n,false);
    for (auto& pr:sp){int to=pr.first,from=pr.second;
        mbedtls_ecp_point_init(&enc_next[to].c1);mbedtls_ecp_point_init(&enc_next[to].c2);
        mbedtls_ecp_copy(&enc_next[to].c1,&enc_state[from].c1);
        mbedtls_ecp_copy(&enc_next[to].c2,&enc_state[from].c2);
        filled[to]=true;}
    for (int s=0;s<n;++s)
        if(!filled[s]){int ret=copy_enc_zero(&enc_next[s]);if(ret)return ret;}
    return 0;}

// =============================================================================
// SECTION 6 — PROBLEM DEFINITIONS  ← ONLY SECTION YOU NEED TO EDIT
// =============================================================================

#define PROBLEM_SMALL_FACTORY          1
#define PROBLEM_EXTENDED_SMALL_FACTORY 2
#define PROBLEM_FMS                    3
#define PROBLEM_CUSTOM                 4

#define ACTIVE_PROBLEM PROBLEM_FMS   // <-- CHANGE THIS LINE

static DFA make_machine(const String& n,const String& s,const String& f){
    DFA m;
    m.name=n;
    m.num_states=2;
    m.initial=0;
    m.marked={true,false};
    m.transitions={{0,s,1},{1,f,0}};
    m.build_delta();
    return m;
}
static DFA make_buffer(const String& n,const String& f,const String& d){
    DFA b;
    b.name=n;
    b.num_states=2;
    b.initial=0;
    b.marked={true,false};
    b.transitions={{0,f,1},{1,d,0}};
    b.build_delta();
    return b;
}

#if ACTIVE_PROBLEM == PROBLEM_SMALL_FACTORY
std::vector<DFA> define_plants(){
    return {
        make_machine("M1","e1","e2"),
        make_machine("M2","e3","e4")};
        }
std::vector<DFA> define_specs(){
    return {
        make_buffer("E","e2","e3")};
        }
std::vector<String> define_simulation_sequence(){
    return {"e1","e2","e3","e1","e4"};
    }

#elif ACTIVE_PROBLEM == PROBLEM_EXTENDED_SMALL_FACTORY
std::vector<DFA> define_plants(){
    return {
        make_machine("M1","a1","b1"),
        make_machine("M2","a2","b2"),
        make_machine("M3","a3","b3")};
        }
std::vector<DFA> define_specs(){
    return {
        make_buffer("B1","b1","a2"),
        make_buffer("B2","b2","a3")};
        }
std::vector<String> define_simulation_sequence(){
    return {"a1","b1","a2","b2","a3","b3","a1","b1"};}

#elif ACTIVE_PROBLEM == PROBLEM_FMS
std::vector<DFA> define_plants(){
    DFA c1;
    c1.name="C1";
    c1.num_states=2;
    c1.initial=0;
    c1.marked={true,false};
    c1.transitions={
        {0,"11",1},
        {1,"12",0}
    };
    c1.build_delta();

    DFA c2;
    c2.name="C2";
    c2.num_states=2;
    c2.initial=0;
    c2.marked={true,false};
    c2.transitions={
        {0,"21",1},
        {1,"22",0}
    };
    c2.build_delta();

    DFA la;
    la.name="Lathe";
    la.num_states=2;
    la.initial=0;
    la.marked={true,false};
    la.transitions={
        {0,"41",1},
        {1,"42",0}
    };
    la.build_delta();

    DFA pd;
    pd.name="PD";
    pd.num_states=2;
    pd.initial=0;
    pd.marked={true,false};
    pd.transitions={
        {0,"81",1},
        {1,"82",0}
    };
    pd.build_delta();

    DFA mi;
    mi.name="Mill";
    mi.num_states=3;
    mi.initial=0;
    mi.marked={true,false,false};
    mi.transitions={
        {0,"51",1},
        {1,"52",0},
        {0,"53",2},
        {2,"54",0}
    };
    mi.build_delta();

    DFA c3;
    c3.name="C3";
    c3.num_states=3;
    c3.initial=0;
    c3.marked={true,false,false};
    c3.transitions={
        {0,"71",1},
        {1,"72",0},
        {0,"73",2},
        {2,"74",0}
    };
    c3.build_delta();
    
    DFA ro;
    ro.name="Robot";
    ro.num_states=6;
    ro.initial=0;
    ro.marked={true,false,false,false,false,false};
    ro.transitions={
        {0,"31",1},
        {1,"32",0},
        {0,"33",2},
        {2,"34",0},
        {0,"35",3},
        {3,"36",0},
        {0,"37",4},
        {4,"38",0},
        {0,"39",5},
        {5,"30",0}
    };
    ro.build_delta();
    
    DFA am;
    am.name="AM";
    am.num_states=4;
    am.initial=0;
    am.marked={true,false,false,false};
    am.transitions={
        {0,"61",1},
        {1,"63",2},
        {1,"65",3},
        {2,"64",0},
        {3,"66",0}
    };
    am.build_delta();
    return {c1,c2,la,mi,ro,am,c3,pd};
}

std::vector<DFA> define_specs(){
    DFA e1=make_buffer("E1","12","31");
    DFA e2=make_buffer("E2","22","33");
    DFA e5=make_buffer("E5","36","61");
    DFA e6=make_buffer("E6","38","63");
    DFA e3;
    e3.name="E3";
    e3.num_states=3;
    e3.initial=0;
    e3.marked={true,false,false};
    e3.transitions={
        {0,"32",1},
        {1,"41",0},
        {0,"42",2},
        {2,"35",0}
    };
    e3.build_delta();

    DFA e7;
    e7.name="E7";
    e7.num_states=3;
    e7.initial=0;
    e7.marked={true,false,false};
    e7.transitions={
        {0,"30",1},
        {1,"71",0},
        {0,"74",2},
        {2,"65",0}
    };
    e7.build_delta();
    DFA e8;
    e8.name="E8";
    e8.num_states=3;
    e8.initial=0;
    e8.marked={true,false,false};
    e8.transitions={
        {0,"72",1},
        {1,"81",0},
        {0,"82",2},
        {2,"73",0}
    };
    e8.build_delta();
    DFA e4;
    e4.name="E4";
    e4.num_states=4;
    e4.initial=0;
    e4.marked={true,false,false,false};
    e4.transitions={
        {0,"34",1},
        {1,"51",0},
        {1,"53",0},
        {0,"52",2},
        {2,"37",0},
        {0,"54",3},
        {3,"39",0}
    };
    e4.build_delta();
    return {e1,e2,e3,e4,e5,e6,e7,e8};}
std::vector<String> define_simulation_sequence(){
    return {"11","12","31","32","41","42","35","36","61","63","64"};}

#elif ACTIVE_PROBLEM == PROBLEM_CUSTOM
std::vector<DFA> define_plants(){
    return {
        make_machine("MA","alpha1","beta1"),
        make_machine("MB","alpha2","beta2")};
    }
std::vector<DFA> define_specs(){
    return {
        make_buffer("BUF","beta1","alpha2")};
    }
std::vector<String> define_simulation_sequence(){
    return {"alpha1","beta1","alpha2","beta2"};}
#endif

// =============================================================================
// SECTION 7 — CLEARTEXT ORACLES (never timed, independent state copies)
// =============================================================================

static std::vector<int> next_state_mono_clr(const std::vector<int>& state,
                                              const String& ev){
    std::vector<int> next(active_automaton.num_states,0);
    if(!B_MATRICES_DENSE.count(ev)) return next;
    const auto& B=B_MATRICES_DENSE.at(ev);
    for (int i=0;i<active_automaton.num_states;++i){
        int s=0;
        for (int j=0;j<active_automaton.num_states;++j) s+=B[i][j]*state[j];
        if(s>0) next[i]=1;}
    return next;}
static std::vector<int> enabled_mono_clr(const std::vector<int>& state){
    int ne=active_automaton.num_events;
    std::vector<int> en(ne,0);
    for (int i=0;i<ne;++i)
        for (int j=0;j<active_automaton.num_states;++j)
            if(R_MATRIX[i][j]&&state[j]){en[i]=1;break;}
    return en;}

// =============================================================================
// SECTION 8 — HOMOMORPHIC STEP FUNCTIONS
// =============================================================================

static int step_monolithic_he(const String& ev,std::vector<int>& dec_en_out){
    if(B_MATRICES_DENSE.count(ev)){
        std::vector<Ciphertext> enc_next;
        int ret=matvec_dense(enc_mono,B_MATRICES_DENSE.at(ev),enc_next);
        if(ret) return ret;
        free_ct_vec(enc_mono);enc_mono=enc_next;}
    std::vector<Ciphertext> enc_en;
    int ret=matvec_dense(enc_mono,R_MATRIX,enc_en);
    if(ret) return ret;
    ret=decrypt_values(enc_en,dec_en_out);
    free_ct_vec(enc_en);return ret;}

// Local modular HE step.
// Encrypted sups: sparse_transition + matvec(R_local, pruned) + decrypt + cache.
// Cleartext sups: integer sparse_transition + integer R_local check.
// Both use independent exec states (clr_lmod_exec for CLR, enc_lmod_states for ENC).
static int step_lmod_he(const String& ev,std::vector<int>& global_en_out){
    int num_ev=global_event_names.size();
    global_en_out.assign(num_ev,1);

    for (size_t i=0;i<lmod_supervisors.size();++i){
        ModSupervisor& ms=lmod_supervisors[i];
        if(ms.encrypted){
            if(ms.own_events.count(ev)){
                std::vector<Ciphertext> enc_next;
                int ret=sparse_transition(enc_lmod_states[i],ms.B_sparse.at(ev),
                                          ms.num_states,enc_next);
                if(ret) return ret;
                free_ct_vec(enc_lmod_states[i]);enc_lmod_states[i]=enc_next;
                std::vector<Ciphertext> enc_en;
                ret=matvec_dense(enc_lmod_states[i],ms.R_local,enc_en);
                if(ret) return ret;
                ret=decrypt_values(enc_en,ms.cached_en);
                free_ct_vec(enc_en);if(ret) return ret;
                ms.cache_valid=true;
            } else {
                if(!ms.cache_valid){
                    std::vector<Ciphertext> enc_en;
                    int ret=matvec_dense(enc_lmod_states[i],ms.R_local,enc_en);
                    if(ret) return ret;
                    ret=decrypt_values(enc_en,ms.cached_en);
                    free_ct_vec(enc_en);if(ret) return ret;
                    ms.cache_valid=true;
                }
            }
            for (size_t li=0;li<ms.own_event_indices.size();++li){
                int gi=ms.own_event_indices[li];
                if(!ms.cached_en[li]) global_en_out[gi]=0;}
        } else {
            // Cleartext path — uses clr_lmod_exec[i], independent of oracle
            std::vector<int>& st=clr_lmod_exec[i];
            if(ms.own_events.count(ev)&&ms.B_sparse.count(ev)){
                const SparseTrans& sp=ms.B_sparse.at(ev);
                std::vector<int> nxt(ms.num_states,0);
                for (auto& pr:sp) nxt[pr.first]=st[pr.second];
                st=nxt;}
            for (size_t li=0;li<ms.own_event_indices.size();++li){
                int gi=ms.own_event_indices[li];
                int e=0;
                for (int s=0;s<ms.num_states;++s)
                    if(ms.R_local[li][s]&&st[s]){e=1;break;}
                if(!e) global_en_out[gi]=0;}
        }
    }
    return 0;}

// =============================================================================
// SECTION 9 — SETUP / LOOP
// =============================================================================

static void print_vec(const std::vector<int>& v){
    Serial.print("[");
    for (size_t i=0;i<v.size();++i)
        Serial.printf("%d%s",v[i],i+1==v.size()?"":","  );
    Serial.print("]");}

void setup(){
    Serial.begin(115200);delay(200);
    Serial.println("\n============================================");
    Serial.println("  DES Homomorphic Benchmark (ESP32 v8d)");
    Serial.println("  Monolithic vs Local Modular");
    Serial.println("============================================\n");

    synthesise_automaton();

    if(mono_he_runnable){
        R_MATRIX=active_automaton.requirements;
        for (size_t i=0;i<active_automaton.event_names.size();++i)
            EVENT_INDEX_MAP[active_automaton.event_names[i]]=(int)i;
        for (const auto& ev:active_automaton.event_names){
            int N=active_automaton.num_states;
            std::vector<std::vector<int>> B(N,std::vector<int>(N,0));
            if(active_automaton.transitions.count(ev))
                for (const auto& t:active_automaton.transitions.at(ev))
                    B[t.second][t.first]=1;
            B_MATRICES_DENSE[ev]=B;}}

    // Crypto init
    grp_ptr      =new mbedtls_ecp_group();        mbedtls_ecp_group_init(grp_ptr);
    G_ptr        =new mbedtls_ecp_point();        mbedtls_ecp_point_init(G_ptr);
    priv_key_ptr =new mbedtls_mpi();              mbedtls_mpi_init(priv_key_ptr);
    pub_key_ptr  =new mbedtls_ecp_point();        mbedtls_ecp_point_init(pub_key_ptr);
    ctr_drbg_ptr =new mbedtls_ctr_drbg_context(); mbedtls_ctr_drbg_init(ctr_drbg_ptr);
    entropy_ptr  =new mbedtls_entropy_context();  mbedtls_entropy_init(entropy_ptr);
    const char* pers="elgamal_des";
    mbedtls_mpi_init(&g_one);mbedtls_mpi_lset(&g_one,1);
    mbedtls_ctr_drbg_seed(ctr_drbg_ptr,mbedtls_entropy_func,entropy_ptr,
                          (const unsigned char*)pers,strlen(pers));
    mbedtls_ecp_group_load(grp_ptr,ELLIPTIC_CURVE);
    mbedtls_ecp_copy(G_ptr,&grp_ptr->G);
    int ret=mbedtls_ecp_gen_keypair(grp_ptr,priv_key_ptr,pub_key_ptr,
                                    mbedtls_ctr_drbg_random,ctr_drbg_ptr);
    if(ret){Serial.printf("Crypto FAILED: -0x%04X\n",-ret);return;}
    mbedtls_ecp_point_init(&g_enc_zero.c1);mbedtls_ecp_point_init(&g_enc_zero.c2);
    ret=ec_elgamal_encrypt(0,&g_enc_zero);
    if(ret){Serial.printf("E(0) FAILED: -0x%04X\n",-ret);return;}
    g_enc_zero_ready=true;
    Serial.println("Crypto ready.\n");

    // Measure actual EC operation costs on this device.
    // muladd (used for homomorphic point addition) and scalar_mul (used for decrypt).
    // These give accurate theoretical estimates for the monolithic HE cost.
    {
        Ciphertext ca, cb;
        ec_elgamal_encrypt(0, &ca);
        ec_elgamal_encrypt(0, &cb);
        // Warm-up muladd
        mbedtls_ecp_point tmp; mbedtls_ecp_point_init(&tmp);
        mbedtls_ecp_muladd(grp_ptr,&tmp,&g_one,&ca.c1,&g_one,&cb.c1);
        mbedtls_ecp_point_free(&tmp);
        // Time muladd (avg of 3)
        long t0=micros();
        for(int _i=0;_i<3;++_i){
            mbedtls_ecp_point t2; mbedtls_ecp_point_init(&t2);
            mbedtls_ecp_muladd(grp_ptr,&t2,&g_one,&ca.c1,&g_one,&cb.c1);
            mbedtls_ecp_point_free(&t2);}
        measured_muladd_us = (micros()-t0)/3;
        // Time scalar_mul (used in decrypt: neg_priv * c1). Avg of 3.
        mbedtls_mpi np; mbedtls_mpi_init(&np);
        mbedtls_mpi_sub_mpi(&np,&grp_ptr->N,priv_key_ptr);
        // Warm-up
        mbedtls_ecp_point ns; mbedtls_ecp_point_init(&ns);
        mbedtls_ecp_mul(grp_ptr,&ns,&np,&ca.c1,mbedtls_ctr_drbg_random,ctr_drbg_ptr);
        mbedtls_ecp_point_free(&ns);
        t0=micros();
        for(int _i=0;_i<3;++_i){
            mbedtls_ecp_point ns2; mbedtls_ecp_point_init(&ns2);
            mbedtls_ecp_mul(grp_ptr,&ns2,&np,&ca.c1,mbedtls_ctr_drbg_random,ctr_drbg_ptr);
            mbedtls_ecp_point_free(&ns2);}
        long measured_scalar_mul_us = (micros()-t0)/3;
        mbedtls_mpi_free(&np);
        mbedtls_ecp_point_free(&ca.c1); mbedtls_ecp_point_free(&ca.c2);
        mbedtls_ecp_point_free(&cb.c1); mbedtls_ecp_point_free(&cb.c2);
        Serial.printf("EC muladd:     %ld us\n", measured_muladd_us);
        Serial.printf("EC scalar_mul: %ld us\n", measured_scalar_mul_us);
        // Store scalar_mul cost for use in theoretical estimate below
        // (decrypt = 1 scalar_mul + 1 muladd per event)
        // We store it in a local that the summary block can access via a global
        // Workaround: encode in measured_muladd_us upper bits — instead use a simple
        // global. We'll just compute decrypt cost inline in the summary.
        // Pass scalar_mul_us to summary via a temporary global approach:
        // Actually simplest: just print it here and use a fixed 80ms for scalar_mul
        // since the measurement is available. We capture it in the summary via closure.
        // Since C++ lambdas are not trivial here, we use a second global.
        // Add measured_scalar_mul_us to global state for use in summary.
        measured_scalar_mul_us_g = measured_scalar_mul_us;
    }

    // Encrypt initial states
    if(mono_he_runnable) encrypt_values(active_automaton.initial_state,enc_mono);
    enc_lmod_states.resize(lmod_supervisors.size());
    clr_lmod_exec.resize(lmod_supervisors.size());
    for (size_t i=0;i<lmod_supervisors.size();++i){
        lmod_supervisors[i].cache_valid=false;
        clr_lmod_exec[i]=lmod_supervisors[i].initial_state;
        if(lmod_supervisors[i].encrypted){
            ret=encrypt_values(lmod_supervisors[i].initial_state,enc_lmod_states[i]);
            if(ret){Serial.printf("Encrypt FAILED sup %d\n",(int)i);return;}
        } else {
            enc_lmod_states[i].clear();
        }
    }

    // Oracle states — completely separate copies
    std::vector<int> oracle_mono;
    if(mono_he_runnable) oracle_mono=active_automaton.initial_state;
    OracleState oracle_lmod;
    oracle_lmod.init(lmod_supervisors);

    const std::vector<String>& seq=active_automaton.simulation_sequence;
    int num_ev=global_event_names.size();
    long total_mono=0,total_lmod=0;
    bool mono_ok=true,lmod_ok=true;

    // Configuration summary
    if(mono_he_runnable)
        Serial.printf("Monolithic : %d states, %d events [HE]\n",
                      active_automaton.num_states,active_automaton.num_events);
    else
        Serial.printf("Monolithic : %d states [HE SKIPPED — too large for device]\n",
                      mono_state_count);
    Serial.println("LocalMod supervisors:");
    for (auto& ms:lmod_supervisors){
        int pruned=(int)ms.own_events.size()-(int)ms.own_event_indices.size();
        Serial.printf("  %-6s: %3d states, %2d own ev, %2d constraining ev"
                      " (pruned %d always-enabled) [%s]\n",
                      ms.name.c_str(),ms.num_states,(int)ms.own_events.size(),
                      (int)ms.own_event_indices.size(),pruned,
                      ms.encrypted?"ENC":"CLR");}
    Serial.println();

    // Benchmark loop
    for (size_t step=0;step<seq.size();++step){
        const String& ev=seq[step];
        Serial.printf("---- Step %d | Event: %s ----\n",(int)step+1,ev.c_str());

        // Single oracle (untimed, independent state).
        // Uses monolithic cleartext when available, lmod cleartext otherwise.
        std::vector<int> oracle_ref;
        if(mono_he_runnable){
            std::vector<int> nc=next_state_mono_clr(oracle_mono,ev);
            oracle_ref=enabled_mono_clr(nc); oracle_mono=nc;
        } else {
            oracle_ref=oracle_lmod.step(lmod_supervisors,ev,num_ev);
        }

        // Monolithic HE
        std::vector<int> mono_en;
        if(mono_he_runnable){
            long t0=micros();
            ret=step_monolithic_he(ev,mono_en);
            total_mono+=micros()-t0;
            if(ret){Serial.printf("  [Mono] ERR -0x%04X\n",-ret);mono_ok=false;}}

        // Local modular HE
        std::vector<int> lmod_en;
        {long t0=micros();
         ret=step_lmod_he(ev,lmod_en);
         total_lmod+=micros()-t0;
         if(ret){Serial.printf("  [LMod] ERR -0x%04X\n",-ret);lmod_ok=false;}}

        // Print — one oracle line, then each approach
        Serial.print("  [Oracle]  en="); print_vec(oracle_ref); Serial.println();
        if(mono_he_runnable){
            Serial.print("  [Mono]    en="); print_vec(mono_en); Serial.println();}
        Serial.print("  [LMod]    en="); print_vec(lmod_en); Serial.println();

        bool mm=mono_he_runnable?(mono_en==oracle_ref):true;
        bool lmd=(lmod_en==oracle_ref);
        if(!mm) mono_ok=false; if(!lmd) lmod_ok=false;
        if(mono_he_runnable) Serial.printf("  Mono:%s  ",mm?"OK":"FAIL");
        Serial.printf("LMod:%s\n\n",lmd?"OK":"FAIL");}

    // Summary
    int ns=(int)seq.size();
    Serial.println("============================================");
    Serial.println("  TIMING SUMMARY");
    Serial.println("============================================");
    if(mono_he_runnable)
        Serial.printf("  Monolithic : %6ld ms total  avg %4ld ms/step\n",
                      total_mono/1000,(total_mono/1000)/ns);
    else{
        // Estimate REAL HE cost including matvec, not just decrypt
        // For n states, m events: matvec(B) = n EC point copies (sparse, free)
        //   matvec(R) = m rows × n EC point adds = m×n EC adds ≈ m×n×1ms
        //   decrypt   = m × 80ms
        // For n=1000, m=31: matvec ≈ 31000ms, decrypt ≈ 2480ms → total ≈ 34s/step
        // Use exact state count + device-measured muladd cost for accurate estimate.
        // R-matvec cost: num_events rows, each row sums ~n/avg_sparsity ciphertexts.
        // Each ciphertext addition = 2 muladd calls (one for c1, one for c2).
        // Sparsity: in a DFA supervisor, events are enabled in roughly 1/k states
        // where k is the average robot cycle length (~6 for FMS).
        int exact_n = mono_state_count;
        int exact_m = num_ev;
        long muladd_ms = measured_muladd_us / 1000;
        if(muladd_ms < 1) muladd_ms = 1;
        long scalar_mul_ms = measured_scalar_mul_us_g / 1000;
        if(scalar_mul_ms < 1) scalar_mul_ms = 1;
        // avg enabled states per R row: Robot has 6 states, each event fires from 1.
        // Events in the monolithic FMS supervisor fire from ~1/6 of states on average.
        long avg_enabled = (long)exact_n / 6;
        if(avg_enabled < 1) avg_enabled = 1;
        // R-matvec: each row sums avg_enabled ciphertexts.
        // Each ciphertext addition = 2 muladd calls (c1 and c2).
        // First term is free (point copy); subsequent terms each cost 1 muladd.
        // So per row: (avg_enabled - 1) × 2 × muladd_ms. Use avg_enabled as upper bound.
        long est_matvec_ms = (long)exact_m * avg_enabled * 2 * muladd_ms;
        // Decrypt: 1 scalar_mul + 1 muladd per event (ec_elgamal_decrypt implementation)
        long est_decrypt_ms_per_ev = scalar_mul_ms + muladd_ms;
        long est_decrypt_ms = (long)exact_m * est_decrypt_ms_per_ev;
        long est_total_ms = est_matvec_ms + est_decrypt_ms;
        Serial.printf("  Monolithic : HE SKIPPED\n");
        Serial.printf("               Supervisor: %d states, %d events\n",exact_n,exact_m);
        Serial.printf("               Measured EC muladd:     %ld ms\n", muladd_ms);
        Serial.printf("               Measured EC scalar_mul: %ld ms\n", scalar_mul_ms);
        Serial.printf("               Est. R-matvec: %ld ms/step\n"
                      "                 (%d ev x ~%ld enabled_st x 2pts x %ld ms/muladd)\n",
                      est_matvec_ms, exact_m, avg_enabled, muladd_ms);
        Serial.printf("               Est. decrypt:  %ld ms/step\n"
                      "                 (%d ev x (%ld scalar_mul + %ld muladd) ms)\n",
                      est_decrypt_ms, exact_m, scalar_mul_ms, muladd_ms);
        Serial.printf("               Est. total HE: ~%ld ms/step\n", est_total_ms);
        Serial.printf("               LMod actual:   %ld ms/step\n", (total_lmod/1000)/ns);
        if(total_lmod>0)
            Serial.printf("               Theoretical speedup: ~%.0fx\n",
                          (float)est_total_ms / ((total_lmod/1000)/ns));}
    Serial.printf("  LocalMod   : %6ld ms total  avg %4ld ms/step\n",
                  total_lmod/1000,(total_lmod/1000)/ns);
    if(mono_he_runnable&&total_lmod>0)
        Serial.printf("  LMod speedup vs Mono: %.2fx\n",(float)total_mono/total_lmod);
    Serial.println();
    {int n_enc=0,n_clr=0,mx_dec=0;
     for (auto& ms:lmod_supervisors){
         ms.encrypted?n_enc++:n_clr++;
         if(ms.encrypted&&(int)ms.own_event_indices.size()>mx_dec)
             mx_dec=ms.own_event_indices.size();}
     Serial.printf("  LMod: %d enc sups, %d clr sups\n",n_enc,n_clr);
     Serial.printf("  Max constraining ev/enc sup: %d (max ~%d ms/active step)\n",
                   mx_dec,mx_dec*80);}
    Serial.println("  (R_local pruning removes always-enabled events from decrypt)");
    Serial.println("  (sparse B = point copies; cache = skip unchanged sups)");
    Serial.println();
    if(mono_he_runnable) Serial.printf("  Mono:%s  ",mono_ok?"PASS":"FAIL");
    Serial.printf("LMod:%s\n",lmod_ok?"PASS":"FAIL");
    Serial.println("============================================\n");

    // Cleanup
    free_ct_vec(enc_mono);
    for (auto& v:enc_lmod_states) free_ct_vec(v);
    mbedtls_ecp_point_free(&g_enc_zero.c1);mbedtls_ecp_point_free(&g_enc_zero.c2);
    mbedtls_mpi_free(&g_one);
    mbedtls_ecp_group_free(grp_ptr);     delete grp_ptr;
    mbedtls_ecp_point_free(G_ptr);       delete G_ptr;
    mbedtls_mpi_free(priv_key_ptr);      delete priv_key_ptr;
    mbedtls_ecp_point_free(pub_key_ptr); delete pub_key_ptr;
    mbedtls_ctr_drbg_free(ctr_drbg_ptr); delete ctr_drbg_ptr;
    mbedtls_entropy_free(entropy_ptr);   delete entropy_ptr;}

void loop(){delay(10000);}
