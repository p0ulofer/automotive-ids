// =============================================================================
// ids_dataset_server.cpp -- servidor SOME/IP parametrizado para geracao de
// datasets normais (Fase 2 do someip-ids / Koyama et al. VTC2022-Spring).
//
// Oferece ate 3 servicos conforme os flags ativos:
//   --rr   : servico 0x1234, metodo 0x0001 (ECHO) com return code OK/NG
//            (probabilidade --p-ng) + eventgroup quase silencioso.
//   --nepc : servico 0x1235, evento 0x8001 periodico (--notify-cycle ms)
//            + metodo 0x0002 (SetMode) que muda o estado drive_mode.
//   --nec  : servico 0x1236, evento 0x8001 SO on-change (compara payload;
//            notifica apenas quando o valor muda) + metodo 0x0003.
//
// Modelo de payload (16 bytes, ver docs/payload_model.md):
//   [0..1] speed uint16 BE | [2..3] steering int16 BE | [4] gear
//   [5] brake(bit0) | [6] acc_state(bits3-5) | [7] turnsignal(bits2-4)
//   [8..15] reservados 0x00
//
// drive_mode A/B/C/D altera a faixa de speed e o padrao de steering
// (dois bit ranges como exige o artigo). Muda via SetMode request ou
// automaticamente a cada --mode-cycle notificacoes.
//
// Seeds fixas (--seed) => reprodutibilidade.
// Saida: exit 0 apos --duration s (ou SIGTERM/SIGINT => parada limpa).
// =============================================================================
#include <vsomeip/vsomeip.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#if defined(__linux__)
#include <pthread.h>
#endif

namespace {

// --- servicos do dataset (Fase 2) ---
constexpr vsomeip::service_t  SVC_RR   = 0x1234;
constexpr vsomeip::service_t  SVC_NEPC = 0x1235;
constexpr vsomeip::service_t  SVC_NEC  = 0x1236;
constexpr vsomeip::instance_t INST     = 0x0001;
constexpr vsomeip::method_t   METH_ECHO    = 0x0001;
constexpr vsomeip::method_t   METH_SETMODE_NEPC = 0x0002;
constexpr vsomeip::method_t   METH_SETMODE_NEC  = 0x0003;
constexpr vsomeip::event_t    EVT_TELEMETRY = 0x8001;
constexpr vsomeip::eventgroup_t EVGRP = 0x0001;

// estados de configuracao (preenchidos no main)
struct Options {
    bool   rr   = false;
    bool   nepc = false;
    bool   nec  = false;
    double p_ng = 0.02;
    uint32_t notify_cycle_ms = 10;
    uint32_t mode_cycle = 50;      // muda modo a cada N notificacoes
    uint32_t seed = 42;
    uint32_t duration_s = 60;
    const char* app_name = "ids-dataset-server";
};

Options g_opt;

// contadores de debug/diagnostico (imprimidos no fim)
std::atomic<uint32_t> g_requests_handled{0};
std::atomic<uint32_t> g_responses_sent{0};
std::atomic<uint32_t> g_setmode_applied{0};
std::mutex g_sent_mu;
std::vector<uint32_t> g_sent_log; // (service<<16)|session de cada RESPONSE enviado

// --- estado por servico ---
struct SvcState {
    int mode = 0;                       // 0=A 1=B 2=C 3=D
    uint32_t notify_count = 0;
    std::array<uint8_t, 16> last_payload{};
    bool has_last = false;
    std::mt19937 rng;
    // contadores de sinal (para variacao suave/reprodutivel)
    double phase_speed = 0.0;
    double phase_steering = 0.0;
    uint8_t gear = 1;
    uint8_t brake = 0;
};

std::map<vsomeip::service_t, SvcState> g_state;

// faixas de speed por modo (constantes do docs/payload_model.md)
static uint16_t speed_base(int mode) {
    switch (mode) {
        case 0: return 20000; // A: 20000..40000
        case 1: return 10000; // B: 10000..30000
        case 2: return 30000; // C: 30000..50000
        default:return 25000; // D: 25000..45000
    }
}
static int steering_amp(int mode) {
    switch (mode) {
        case 0: return 1000;  // A: -1000..1000
        case 1: return 2000;  // B: -2000..2000
        case 2: return 500;   // C: -500..500
        default:return 1500;  // D: -1500..1500
    }
}
// faixa de gear por modo (limites validos 0..6)
static void gear_bounds(int mode, uint8_t& lo, uint8_t& hi) {
    switch (mode) {
        case 0: lo=1; hi=3; break; // A: 1-3
        case 1: lo=1; hi=4; break; // B: 1-4
        case 2: lo=2; hi=5; break; // C: 2-5
        default:lo=3; hi=5; break; // D: 3-5
    }
}

// gera payload de 16 bytes para um servico (modifica estado interno)
void gen_payload(vsomeip::service_t svc, std::array<uint8_t,16>& out) {
    auto& st = g_state[svc];
    auto& rng = st.rng;

    // speed: seno suave dentro da faixa do modo + jitter rng
    st.phase_speed += 2.0 * M_PI / 20.0;            // periodo 20 ciclos
    if (st.phase_speed > 2.0 * M_PI) st.phase_speed -= 2.0 * M_PI;
    double amp = (speed_base(st.mode + 1) - speed_base(st.mode)) / 2.0;
    double center = speed_base(st.mode) + amp;
    uint16_t speed = static_cast<uint16_t>(center + amp * std::sin(st.phase_speed)
                                           + (rng() % 5));  // +-5

    // steering: seno com amplitude do modo, sinal invertido se gear mudou
    st.phase_steering += 2.0 * M_PI / 15.0;
    if (st.phase_steering > 2.0 * M_PI) st.phase_steering -= 2.0 * M_PI;
    int32_t steer = static_cast<int32_t>(steering_amp(st.mode) * std::sin(st.phase_steering));

    // gear: transicoes validas (+-1 dentro dos limites do modo)
    uint8_t lo, hi; gear_bounds(st.mode, lo, hi);
    if (rng() % 8 == 0) { // ~12% de chance de trocar
        int step = (rng() % 2) ? 1 : -1;
        int g = static_cast<int>(st.gear) + step;
        if (g < lo) g = lo;
        if (g > hi) g = hi;
        st.gear = static_cast<uint8_t>(g);
    }

    // brake: 2% de probabilidade por payload
    if (rng() % 50 == 0) st.brake ^= 1;

    // acc_state: default por modo; forcado 0 (Off) se brake=1
    static const uint8_t mode_acc[4] = {1, 3, 2, 1}; // A Resume, B Coast, C Set, D Resume
    uint8_t acc = st.brake ? 0 : mode_acc[st.mode];

    // turnsignal: default por modo; em modo D alterna rapido (hazard)
    static const uint8_t mode_sig[4] = {0, 1, 2, 3};
    uint8_t sig = mode_sig[st.mode];
    if (st.mode == 3) sig = (st.notify_count / 3) % 2 ? 1 : 2; // Left/Right alternado

    // montagem big-endian
    out.fill(0);
    out[0] = static_cast<uint8_t>(speed >> 8);
    out[1] = static_cast<uint8_t>(speed & 0xFF);
    int16_t s16 = static_cast<int16_t>(steer);
    out[2] = static_cast<uint8_t>(static_cast<uint16_t>(s16) >> 8);
    out[3] = static_cast<uint8_t>(static_cast<uint16_t>(s16) & 0xFF);
    out[4] = st.gear;
    out[5] = st.brake ? 0x01 : 0x00;
    out[6] = static_cast<uint8_t>((acc & 0x07) << 3);
    out[7] = static_cast<uint8_t>((sig & 0x07) << 2);

    st.notify_count++;
    // modo automatico a cada mode_cycle notificacoes (cicla A->B->C->D->A)
    if (g_opt.mode_cycle > 0 && st.notify_count % g_opt.mode_cycle == 0) {
        st.mode = (st.mode + 1) % 4;
    }
}

// aplica SetMode (request method) a um servico
void apply_setmode(vsomeip::service_t svc, uint8_t new_mode) {
    auto it = g_state.find(svc);
    if (it == g_state.end()) return;
    if (new_mode > 3) new_mode = 3;
    it->second.mode = new_mode;
    it->second.notify_count = 0; // reinicia ciclo de modo automatico
    const char* names[] = {"A","B","C","D"};
    std::cout << "[ds_server] SetMode svc=0x" << std::hex << svc
              << " -> modo " << names[new_mode] << std::dec << std::endl;
}

} // namespace

// =============================================================================
// classe principal
// =============================================================================
class dataset_server {
public:
    explicit dataset_server(const Options& opt)
        : app_(vsomeip::runtime::get()->create_application(opt.app_name)),
          notify_thread_(&dataset_server::notify_loop, this) {}

    bool init() {
        if (!app_->init()) {
            std::cerr << "[ds_server] app->init() falhou" << std::endl;
            return false;
        }
        app_->register_state_handler(
            [this](vsomeip::state_type_e s) { on_state(s); });

        // handler unico para requests nos servicos ativos
        auto handler = [this](const std::shared_ptr<vsomeip::message>& m) {
            on_message(m);
        };
        if (g_opt.rr)
            app_->register_message_handler(SVC_RR, INST, METH_ECHO, handler);
        if (g_opt.nepc)
            app_->register_message_handler(SVC_NEPC, INST, METH_SETMODE_NEPC, handler);
        if (g_opt.nec)
            app_->register_message_handler(SVC_NEC, INST, METH_SETMODE_NEC, handler);

        // eventos nos servicos: RR oferece o eventgroup mas notifica raramente
        // ("assinatura existe, quase nao gera notificacoes" -- artigo)
        if (g_opt.rr || g_opt.nepc || g_opt.nec) {
            std::set<vsomeip::eventgroup_t> groups{EVGRP};
            auto offer = [&](vsomeip::service_t svc) {
                app_->offer_event(svc, INST, EVT_TELEMETRY, groups,
                    vsomeip::event_type_e::ET_EVENT, std::chrono::milliseconds::zero(),
                    false, true, nullptr, vsomeip::reliability_type_e::RT_UNRELIABLE);
            };
            if (g_opt.rr)   offer(SVC_RR);
            if (g_opt.nepc) offer(SVC_NEPC);
            if (g_opt.nec)  offer(SVC_NEC);
        }
        std::cout << "[ds_server] init ok (rr=" << g_opt.rr
                  << " nepc=" << g_opt.nepc << " nec=" << g_opt.nec
                  << " p_ng=" << g_opt.p_ng
                  << " notify_cycle=" << g_opt.notify_cycle_ms << "ms"
                  << " mode_cycle=" << g_opt.mode_cycle
                  << " seed=" << g_opt.seed << ")" << std::endl;
        return true;
    }

    void start() { app_->start(); }
    void stop() {
        running_ = false;
        cv_.notify_all();
        if (notify_thread_.joinable()) notify_thread_.join();
        app_->clear_all_handler();
        if (g_opt.rr)   app_->stop_offer_service(SVC_RR, INST);
        if (g_opt.nepc) app_->stop_offer_service(SVC_NEPC, INST);
        if (g_opt.nec)  app_->stop_offer_service(SVC_NEC, INST);
        app_->stop();
    }

private:
    void on_state(vsomeip::state_type_e s) {
        if (s == vsomeip::state_type_e::ST_REGISTERED) {
            if (g_opt.rr)   app_->offer_service(SVC_RR, INST);
            if (g_opt.nepc) app_->offer_service(SVC_NEPC, INST);
            if (g_opt.nec)  app_->offer_service(SVC_NEC, INST);
            registered_ = true;
            cv_.notify_all();
            std::cout << "[ds_server] registrado; servicos em oferta" << std::endl;
        } else {
            registered_ = false;
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message>& m) {
        const auto svc = m->get_service();
        const auto meth = m->get_method();
        const auto mtype = m->get_message_type();

        if (mtype != vsomeip::message_type_e::MT_REQUEST) return;
        g_requests_handled++;

        // payload de request: byte0 = novo modo (SetMode) ou dado (ECHO)
        uint8_t mode_byte = 0;
        if (auto p = m->get_payload(); p && p->get_length() > 0) {
            const vsomeip::byte_t* data = p->get_data();
            if (data) mode_byte = data[0];
        }

        if ((svc == SVC_NEPC && meth == METH_SETMODE_NEPC) ||
            (svc == SVC_NEC  && meth == METH_SETMODE_NEC)) {
            apply_setmode(svc, mode_byte);
            g_setmode_applied++;
        }

        // resposta com return code OK ou NG conforme p_ng
        auto resp = vsomeip::runtime::get()->create_response(m);
        std::mt19937 rng(g_opt.seed + static_cast<uint32_t>(svc) + m->get_session());
        const bool ng = (g_opt.p_ng > 0.0) &&
                        (std::generate_canonical<double, 32>(rng) < g_opt.p_ng);
        if (ng) {
            resp->set_return_code(vsomeip::return_code_e::E_NOT_OK);
        }
        // payload de resposta: echo do byte0 + modo atual
        std::vector<vsomeip::byte_t> rdata(4, 0x22);
        rdata[0] = mode_byte;
        if (auto it = g_state.find(svc); it != g_state.end()) {
            rdata[1] = static_cast<uint8_t>(it->second.mode);
        }
        auto rp = vsomeip::runtime::get()->create_payload();
        rp->set_data(rdata);
        resp->set_payload(rp);
        app_->send(resp);
        g_responses_sent++;
        {
            std::lock_guard<std::mutex> lk(g_sent_mu);
            g_sent_log.push_back(
                (static_cast<uint32_t>(svc) << 16) | resp->get_session());
        }
    }

    void notify_loop() {
        {
            std::unique_lock<std::mutex> lock(m_);
            cv_.wait(lock, [this] { return !running_ || registered_.load(); });
        }
        if (!running_) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        const bool periodic = g_opt.nepc;   // NEpc: periodico
        const bool onchange = g_opt.nec;    // NEC: so on-change
        // RR: notificacao rarissima (a cada ~30s) -- quase nao gera
        const uint32_t rr_every = std::max<uint32_t>(1, 30000 / g_opt.notify_cycle_ms);
        uint32_t tick = 0;

        while (running_) {
            if (periodic) {
                std::array<uint8_t, 16> pl{};
                gen_payload(SVC_NEPC, pl);
                auto p = vsomeip::runtime::get()->create_payload();
                p->set_data(pl.data(), pl.size());
                app_->notify(SVC_NEPC, INST, EVT_TELEMETRY, p);
            }
            if (onchange) {
                std::array<uint8_t, 16> pl{};
                gen_payload(SVC_NEC, pl);
                auto& st = g_state[SVC_NEC];
                if (!st.has_last || pl != st.last_payload) {
                    st.last_payload = pl;
                    st.has_last = true;
                    auto p = vsomeip::runtime::get()->create_payload();
                    p->set_data(pl.data(), pl.size());
                    app_->notify(SVC_NEC, INST, EVT_TELEMETRY, p);
                }
            }
            if (g_opt.rr && (++tick % rr_every == 0)) {
                std::array<uint8_t, 16> pl{};
                gen_payload(SVC_RR, pl);
                auto p = vsomeip::runtime::get()->create_payload();
                p->set_data(pl.data(), pl.size());
                app_->notify(SVC_RR, INST, EVT_TELEMETRY, p);
            }
            std::unique_lock<std::mutex> lock(m_);
            cv_.wait_for(lock, std::chrono::milliseconds(g_opt.notify_cycle_ms),
                         [this] { return !running_; });
        }
    }

    std::shared_ptr<vsomeip::application> app_;
    std::thread notify_thread_;
    std::mutex m_;
    std::condition_variable cv_;
    std::atomic<bool> registered_{false};
    std::atomic<bool> running_{true};
};

// =============================================================================
int main(int argc, char** argv) {
    Options opt;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--rr") opt.rr = true;
        else if (a == "--nepc") opt.nepc = true;
        else if (a == "--nec") opt.nec = true;
        else if (a == "--p-ng") opt.p_ng = std::stod(next());
        else if (a == "--notify-cycle") opt.notify_cycle_ms = std::stoul(next());
        else if (a == "--mode-cycle") opt.mode_cycle = std::stoul(next());
        else if (a == "--seed") opt.seed = std::stoul(next());
        else if (a == "--duration") opt.duration_s = std::stoul(next());
        else if (a == "--app-name") opt.app_name = next();
        else {
            std::cerr << "uso: ids_dataset_server [--rr] [--nepc] [--nec]"
                      << " [--p-ng F] [--notify-cycle MS] [--mode-cycle N]"
                      << " [--seed N] [--duration S] [--app-name NAME]" << std::endl;
            return 1;
        }
    }
    if (!opt.rr && !opt.nepc && !opt.nec) opt.rr = opt.nepc = opt.nec = true;
    g_opt = opt; // copia para o global lido pelos handlers

    // seeds por servico (reprodutibilidade)
    g_state[SVC_RR].rng.seed(opt.seed + 0x1234);
    g_state[SVC_NEPC].rng.seed(opt.seed + 0x1235);
    g_state[SVC_NEC].rng.seed(opt.seed + 0x1236);

    // sinais bloqueados -> thread dedicada com sigwait
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigs, nullptr);

    dataset_server srv(opt);
    if (!srv.init()) return 1;

    std::thread sigwatch([&sigs, &srv]() {
        int s = 0;
        if (sigwait(&sigs, &s) == 0) {
            std::cout << "[ds_server] sinal " << s << " recebido" << std::endl;
            srv.stop();
        }
    });

    // timer de duracao (exit 0)
    std::thread timer([opt, &srv]() {
        std::this_thread::sleep_for(std::chrono::seconds(opt.duration_s));
        std::cout << "[ds_server] duracao atingida (" << opt.duration_s
                  << "s); a terminar" << std::endl;
        srv.stop();
        ::kill(::getpid(), SIGTERM);
    });

    srv.start(); // bloqueia ate stop()

    if (timer.joinable()) timer.join();
    if (sigwatch.joinable()) sigwatch.join();
    std::cout << "[ds_server] contadores: requests_handled=" << g_requests_handled
              << " responses_sent=" << g_responses_sent
              << " setmode_applied=" << g_setmode_applied << std::endl;
    if (const char* dbg = ::getenv("DS_SESSION_LOG"); dbg && dbg[0] == '1') {
        std::lock_guard<std::mutex> lk(g_sent_mu);
        for (auto v : g_sent_log)
            std::cout << "[ds_server] resp ses svc=0x" << std::hex
                      << (v >> 16) << " ses=" << (v & 0xFFFF) << std::dec
                      << "\n";
    }
    std::cout.flush();
    std::cout << "[ds_server] encerrado" << std::endl;
    return 0;
}