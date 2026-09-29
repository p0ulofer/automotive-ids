// =============================================================================
// ids_dataset_client.cpp -- cliente SOME/IP parametrizado para geracao de
// datasets normais (Fase 2 do someip-ids).
//
// Flags:
//   --rr   : pede servico 0x1234, envia ECHO (metodo 0x0001) a cada --cycle ms,
//            subscreve o eventgroup 0x0001 (quase silencioso).
//   --nepc : pede servico 0x1235, subscreve evento 0x8001, envia SetMode
//            (metodo 0x0002) a cada --setmode-cycle notificacoes recebidas.
//   --nec  : pede servico 0x1236, subscreve evento 0x8001, envia SetMode
//            (metodo 0x0003) ocasionalmente.
//
// Termina com exit 0 apos --duration s (ou --exit-on-timeout por omissao),
// contando respostas e notificacoes.
// =============================================================================
#include <vsomeip/vsomeip.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
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
constexpr vsomeip::service_t  SVC_RR   = 0x1234;
constexpr vsomeip::service_t  SVC_NEPC = 0x1235;
constexpr vsomeip::service_t  SVC_NEC  = 0x1236;
constexpr vsomeip::instance_t INST     = 0x0001;
constexpr vsomeip::method_t   METH_ECHO    = 0x0001;
constexpr vsomeip::method_t   METH_SETMODE_NEPC = 0x0002;
constexpr vsomeip::method_t   METH_SETMODE_NEC  = 0x0003;
constexpr vsomeip::event_t    EVT_TELEMETRY = 0x8001;
constexpr vsomeip::eventgroup_t EVGRP = 0x0001;

struct Options {
    bool rr = false, nepc = false, nec = false;
    uint32_t cycle_ms = 100;          // periodo de requests
    uint32_t setmode_every = 0;       // SetMode a cada N notifs (0 = nunca)
    uint32_t seed = 42;
    uint32_t duration_s = 60;
    const char* app_name = "ids-dataset-client";
};
Options g_opt;

std::atomic<uint32_t> responses_{0};
std::atomic<uint32_t> ng_count_{0};
std::atomic<uint32_t> notifications_{0};
std::atomic<uint32_t> requests_sent_{0};
std::atomic<bool> available_rr_{false};
std::atomic<bool> available_nepc_{false};
std::atomic<bool> available_nec_{false};
std::atomic<bool> running_{true};
std::mutex g_resp_mu;
std::vector<uint32_t> g_resp_log; // (service<<16)|session de cada RESPONSE recebido
} // namespace

class dataset_client {
public:
    explicit dataset_client(const Options& opt)
        : app_(vsomeip::runtime::get()->create_application(opt.app_name)),
          req_rr_(vsomeip::runtime::get()->create_request(false)),
          req_nepc_(vsomeip::runtime::get()->create_request(false)),
          req_nec_(vsomeip::runtime::get()->create_request(false)),
          sender_(&dataset_client::send_loop, this) {}

    bool init() {
        if (!app_->init()) return false;

        app_->register_state_handler([this](vsomeip::state_type_e s) {
            if (s == vsomeip::state_type_e::ST_REGISTERED) {
                if (g_opt.rr)   app_->request_service(SVC_RR, INST);
                if (g_opt.nepc) app_->request_service(SVC_NEPC, INST);
                if (g_opt.nec)  app_->request_service(SVC_NEC, INST);
                std::cout << "[ds_client] registrado" << std::endl;
            } else {
                available_rr_ = available_nepc_ = available_nec_ = false;
            }
        });

        app_->register_message_handler(
            vsomeip::ANY_SERVICE, INST, vsomeip::ANY_METHOD,
            [this](const std::shared_ptr<vsomeip::message>& m) { on_message(m); });

        if (g_opt.rr)
            app_->register_availability_handler(SVC_RR, INST,
                [](vsomeip::service_t, vsomeip::instance_t, bool a) {
                    available_rr_ = a;
                });
        if (g_opt.nepc)
            app_->register_availability_handler(SVC_NEPC, INST,
                [](vsomeip::service_t, vsomeip::instance_t, bool a) {
                    available_nepc_ = a;
                });
        if (g_opt.nec)
            app_->register_availability_handler(SVC_NEC, INST,
                [](vsomeip::service_t, vsomeip::instance_t, bool a) {
                    available_nec_ = a;
                });

        // subscricoes de evento (RR tem eventgroup "quase silencioso")
        if (g_opt.rr || g_opt.nepc || g_opt.nec) {
            std::set<vsomeip::eventgroup_t> groups{EVGRP};
            if (g_opt.rr) {
                app_->request_event(SVC_RR, INST, EVT_TELEMETRY, groups,
                    vsomeip::event_type_e::ET_EVENT,
                    vsomeip::reliability_type_e::RT_UNRELIABLE);
                app_->subscribe(SVC_RR, INST, EVGRP);
            }
            if (g_opt.nepc) {
                app_->request_event(SVC_NEPC, INST, EVT_TELEMETRY, groups,
                    vsomeip::event_type_e::ET_EVENT,
                    vsomeip::reliability_type_e::RT_UNRELIABLE);
                app_->subscribe(SVC_NEPC, INST, EVGRP);
            }
            if (g_opt.nec) {
                app_->request_event(SVC_NEC, INST, EVT_TELEMETRY, groups,
                    vsomeip::event_type_e::ET_EVENT,
                    vsomeip::reliability_type_e::RT_UNRELIABLE);
                app_->subscribe(SVC_NEC, INST, EVGRP);
            }
        }

        // prepara requests
        if (g_opt.rr) {
            req_rr_->set_service(SVC_RR);
            req_rr_->set_instance(INST);
            req_rr_->set_method(METH_ECHO);
        }
        if (g_opt.nepc) {
            req_nepc_->set_service(SVC_NEPC);
            req_nepc_->set_instance(INST);
            req_nepc_->set_method(METH_SETMODE_NEPC);
        }
        if (g_opt.nec) {
            req_nec_->set_service(SVC_NEC);
            req_nec_->set_instance(INST);
            req_nec_->set_method(METH_SETMODE_NEC);
        }

        std::cout << "[ds_client] init ok (rr=" << g_opt.rr
                  << " nepc=" << g_opt.nepc << " nec=" << g_opt.nec
                  << " cycle=" << g_opt.cycle_ms << "ms)" << std::endl;
        return true;
    }

    void start() { app_->start(); }
    void stop() {
        running_ = false;
        cv_.notify_all();
        if (sender_.joinable()) sender_.join();
        app_->clear_all_handler();
        if (g_opt.rr)   app_->unsubscribe(SVC_RR, INST, EVGRP);
        if (g_opt.nepc) app_->unsubscribe(SVC_NEPC, INST, EVGRP);
        if (g_opt.nec)  app_->unsubscribe(SVC_NEC, INST, EVGRP);
        app_->stop();
    }

private:
    void on_message(const std::shared_ptr<vsomeip::message>& m) {
        const auto mtype = m->get_message_type();
        if (mtype == vsomeip::message_type_e::MT_RESPONSE) {
            responses_++;
            if (m->get_return_code() != vsomeip::return_code_e::E_OK) ng_count_++;
            std::lock_guard<std::mutex> lk(g_resp_mu);
            g_resp_log.push_back(
                (static_cast<uint32_t>(m->get_service()) << 16) | m->get_session());
        } else if (mtype == vsomeip::message_type_e::MT_NOTIFICATION) {
            notifications_++;
        }
    }

    void send_loop() {
        uint32_t seq = 0;
        uint32_t cycle_count = 0;
        while (running_) {
            {
                std::unique_lock<std::mutex> lock(m_);
                cv_.wait_for(lock, std::chrono::milliseconds(g_opt.cycle_ms),
                             [this] { return !running_; });
            }
            if (!running_) break;
            cycle_count++;

            // ECHO request (RR)
            if (g_opt.rr && available_rr_) {
                std::vector<vsomeip::byte_t> data(16, 0x11);
                data[0] = static_cast<uint8_t>(seq >> 24);
                data[1] = static_cast<uint8_t>(seq >> 16);
                data[2] = static_cast<uint8_t>(seq >> 8);
                data[3] = static_cast<uint8_t>(seq);
                auto p = vsomeip::runtime::get()->create_payload();
                p->set_data(data);
                req_rr_->set_payload(p);
                app_->send(req_rr_);
                requests_sent_++;
            }
            // SetMode (NEpc): rotaciona modos A->B->C->D para cobrir todas as
            // faixas do payload durante o dataset
            if (g_opt.nepc && available_nepc_) {
                const uint32_t every =
                    g_opt.setmode_every > 0 ? g_opt.setmode_every : 50;
                if (cycle_count % every == 0) {
                    uint8_t mode = static_cast<uint8_t>((seq / every) % 4);
                    std::vector<vsomeip::byte_t> data{mode, 0x00};
                    auto p = vsomeip::runtime::get()->create_payload();
                    p->set_data(data);
                    req_nepc_->set_payload(p);
                    app_->send(req_nepc_);
                    requests_sent_++;
                }
            }
            // SetMode (NEc): menos frequente; periodo vem do YAML
            // (setmode_every_cycles, 200 se nao indicado)
            if (g_opt.nec && available_nec_) {
                const uint32_t every =
                    g_opt.setmode_every > 0 ? g_opt.setmode_every : 200;
                if (cycle_count % every == 0) {
                    uint8_t mode = static_cast<uint8_t>((seq / every) % 4);
                    std::vector<vsomeip::byte_t> data{mode, 0x00};
                    auto p = vsomeip::runtime::get()->create_payload();
                    p->set_data(data);
                    req_nec_->set_payload(p);
                    app_->send(req_nec_);
                    requests_sent_++;
                }
            }
            seq++;
        }
    }

    std::shared_ptr<vsomeip::application> app_;
    std::shared_ptr<vsomeip::message> req_rr_, req_nepc_, req_nec_;
    std::thread sender_;
    std::mutex m_;
    std::condition_variable cv_;
};

int main(int argc, char** argv) {
    Options opt;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> const char* { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--rr") opt.rr = true;
        else if (a == "--nepc") opt.nepc = true;
        else if (a == "--nec") opt.nec = true;
        else if (a == "--cycle") opt.cycle_ms = std::stoul(next());
        else if (a == "--setmode-every") opt.setmode_every = std::stoul(next());
        else if (a == "--seed") opt.seed = std::stoul(next());
        else if (a == "--duration") opt.duration_s = std::stoul(next());
        else if (a == "--app-name") opt.app_name = next();
        else {
            std::cerr << "uso: ids_dataset_client [--rr] [--nepc] [--nec]"
                      << " [--cycle MS] [--setmode-every N] [--seed N]"
                      << " [--duration S] [--app-name NAME]" << std::endl;
            return 1;
        }
    }
    if (!opt.rr && !opt.nepc && !opt.nec) opt.rr = opt.nepc = opt.nec = true;
    g_opt = opt; // copia para o global lido pelos handlers

    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigs, nullptr);

    dataset_client cli(opt);
    if (!cli.init()) return 1;

    std::thread sigwatch([&sigs, &cli]() {
        int s = 0;
        if (sigwait(&sigs, &s) == 0) {
            std::cout << "[ds_client] sinal " << s << " recebido" << std::endl;
            cli.stop();
        }
    });

    std::thread timer([opt, &cli]() {
        std::this_thread::sleep_for(std::chrono::seconds(opt.duration_s));
        std::cout << "[ds_client] fim: requests=" << requests_sent_
                  << " responses=" << responses_ << " ng=" << ng_count_
                  << " notifications=" << notifications_ << std::endl;
        if (const char* dbg = ::getenv("DS_SESSION_LOG"); dbg && dbg[0] == '1') {
            std::lock_guard<std::mutex> lk(g_resp_mu);
            for (auto v : g_resp_log)
                std::cout << "[ds_client] resp ses svc=0x" << std::hex
                          << (v >> 16) << " ses=" << (v & 0xFFFF) << std::dec
                          << "\n";
        }
        std::cout.flush();
        cli.stop();
        ::kill(::getpid(), SIGTERM);
    });

    cli.start();

    if (timer.joinable()) timer.join();
    if (sigwatch.joinable()) sigwatch.join();
    std::cout << "[ds_client] PASS responses=" << responses_
              << " ng=" << ng_count_
              << " notifications=" << notifications_ << std::endl;
    return 0;
}