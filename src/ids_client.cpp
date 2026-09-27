// =============================================================================
// ids_client.cpp -- cliente SOME/IP (roda em ecu1, IP 192.168.1.2)
//
//  * Servico A (0x1234.0001): envia o metodo ECHO periodicamente e aguarda
//                             a resposta  -> Request/Response.
//  * Servico B (0x1235.0001): assina o eventgroup 0x0001 e recebe as
//                             notificacoes do evento TELEMETRY 0x8001.
//
// O processo termina com exit code 0 assim que tiver recebido pelo menos
// MIN_RESPONSES respostas E MIN_NOTIFICATIONS notificacoes (dentro do timeout),
// ou com exit code 1 em caso de timeout -- e isso que o smoke test verifica.
// =============================================================================
#include <vsomeip/vsomeip.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#if defined(__linux__)
#include <pthread.h>
#endif

#include "ids.hpp"

namespace {
constexpr std::uint32_t MIN_RESPONSES = 3;
constexpr std::uint32_t MIN_NOTIFICATIONS = 3;
constexpr std::uint32_t DEFAULT_REQUEST_CYCLE_MS = 500;
constexpr std::uint32_t DEFAULT_TIMEOUT_S = 60;
} // namespace

class ids_client {
public:
    explicit ids_client(std::uint32_t _request_cycle_ms)
        : app_(vsomeip::runtime::get()->create_application(ids::APP_CLIENT)),
          request_(vsomeip::runtime::get()->create_request(false /*udp*/)),
          request_cycle_ms_(_request_cycle_ms),
          sender_thread_(&ids_client::send_loop, this) {}

    bool init() {
        if (!app_->init()) {
            std::cerr << "[ids_client] app->init() falhou" << std::endl;
            return false;
        }

        app_->register_state_handler([this](vsomeip::state_type_e _state) { on_state(_state); });

        // Um handler cobre tanto as respostas (servico A) quanto as
        // notificacoes (servico B) -- mesma instancia 0x0001.
        app_->register_message_handler(
                vsomeip::ANY_SERVICE, ids::INSTANCE, vsomeip::ANY_METHOD,
                [this](const std::shared_ptr<vsomeip::message>& _msg) { on_message(_msg); });

        app_->register_availability_handler(
                ids::SERVICE_REQRESP, ids::INSTANCE,
                [this](vsomeip::service_t _service, vsomeip::instance_t _instance, bool _is_available) {
                    on_availability(_service, _instance, _is_available);
                });
        app_->register_availability_handler(
                ids::SERVICE_EVENTS, ids::INSTANCE,
                [this](vsomeip::service_t _service, vsomeip::instance_t _instance, bool _is_available) {
                    on_availability(_service, _instance, _is_available);
                });

        // Assina o eventgroup do servico B.
        std::set<vsomeip::eventgroup_t> its_groups;
        its_groups.insert(ids::EVENTGROUP_TELEMETRY);
        app_->request_event(ids::SERVICE_EVENTS, ids::INSTANCE, ids::EVENT_TELEMETRY, its_groups,
                            vsomeip::event_type_e::ET_EVENT,
                            vsomeip::reliability_type_e::RT_UNRELIABLE);
        app_->subscribe(ids::SERVICE_EVENTS, ids::INSTANCE, ids::EVENTGROUP_TELEMETRY);

        request_->set_service(ids::SERVICE_REQRESP);
        request_->set_instance(ids::INSTANCE);
        request_->set_method(ids::METHOD_ECHO);

        std::cout << "[ids_client] init ok (request " << std::hex << std::setfill('0')
                  << std::setw(4) << ids::SERVICE_REQRESP << "." << std::setw(4) << ids::INSTANCE
                  << " method " << std::setw(4) << ids::METHOD_ECHO << " | subscribe "
                  << std::setw(4) << ids::SERVICE_EVENTS << " event " << std::setw(4)
                  << ids::EVENT_TELEMETRY << ")" << std::dec << std::endl;
        return true;
    }

    void start() { app_->start(); }

    void request_stop() {
        bool expected = false;
        if (stop_requested_.compare_exchange_strong(expected, true)) {
            running_ = false;
            sender_cv_.notify_all();
            if (sender_thread_.joinable()) {
                sender_thread_.join();
            }
            app_->clear_all_handler();
            app_->unsubscribe(ids::SERVICE_EVENTS, ids::INSTANCE, ids::EVENTGROUP_TELEMETRY);
            app_->release_event(ids::SERVICE_EVENTS, ids::INSTANCE, ids::EVENT_TELEMETRY);
            app_->release_service(ids::SERVICE_REQRESP, ids::INSTANCE);
            app_->release_service(ids::SERVICE_EVENTS, ids::INSTANCE);
            app_->stop();
        }
    }

    void join_sender() {
        running_ = false;
        sender_cv_.notify_all();
        if (sender_thread_.joinable()) {
            sender_thread_.join();
        }
    }

    void mark_success() { success_ = true; }
    bool success() const { return success_.load(); }
    std::uint32_t responses() const { return responses_.load(); }
    std::uint32_t notifications() const { return notifications_.load(); }
    bool service_available() const { return service_available_.load(); }

private:
    void on_state(vsomeip::state_type_e _state) {
        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            app_->request_service(ids::SERVICE_REQRESP, ids::INSTANCE);
            app_->request_service(ids::SERVICE_EVENTS, ids::INSTANCE);
            std::cout << "[ids_client] registrado; pedindo 0x"
                      << std::hex << std::setfill('0') << std::setw(4) << ids::SERVICE_REQRESP
                      << " e 0x" << std::setw(4) << ids::SERVICE_EVENTS << std::dec << std::endl;
        } else {
            service_available_ = false;
            std::cout << "[ids_client] deregistrado" << std::endl;
        }
    }

    void on_availability(vsomeip::service_t _service, vsomeip::instance_t _instance, bool _is_available) {
        if (_service == ids::SERVICE_REQRESP && _instance == ids::INSTANCE) {
            service_available_ = _is_available;
            std::cout << "[ids_client] servico " << std::hex << std::setfill('0')
                      << std::setw(4) << _service << "." << std::setw(4) << _instance << std::dec
                      << (_is_available ? " DISPONIVEL" : " INDISPONIVEL") << std::endl;
        } else if (_service == ids::SERVICE_EVENTS && _instance == ids::INSTANCE) {
            std::cout << "[ids_client] servico " << std::hex << std::setfill('0')
                      << std::setw(4) << _service << "." << std::setw(4) << _instance << std::dec
                      << (_is_available ? " DISPONIVEL" : " INDISPONIVEL") << std::endl;
        }
    }

    void on_message(const std::shared_ptr<vsomeip::message>& _msg) {
        if (_msg->get_service() == ids::SERVICE_REQRESP && _msg->get_method() == ids::METHOD_ECHO
            && _msg->get_message_type() == vsomeip::message_type_e::MT_RESPONSE) {
            const std::uint32_t n = ++responses_;
            if (n <= 3 || (n % 10) == 0) {
                std::cout << "[ids_client] RESPOSTA #" << std::dec << n
                          << " (session=0x" << std::hex << std::setfill('0') << std::setw(4)
                          << _msg->get_session() << std::dec << ", payload="
                          << _msg->get_payload()->get_length() << " B)" << std::endl;
            }
        } else if (_msg->get_service() == ids::SERVICE_EVENTS
                   && _msg->get_method() == ids::EVENT_TELEMETRY) {
            const std::uint32_t n = ++notifications_;
            if (n <= 3 || (n % 10) == 0) {
                std::cout << "[ids_client] NOTIFICACAO #" << std::dec << n
                          << " (payload=" << _msg->get_payload()->get_length() << " B)" << std::endl;
            }
        }
    }

    void send_loop() {
        std::uint32_t seq = 0;
        while (running_) {
            {
                std::unique_lock<std::mutex> lock(sender_mutex_);
                sender_cv_.wait_for(lock, std::chrono::milliseconds(request_cycle_ms_),
                                    [this] { return !running_; });
            }
            if (!running_ || !service_available_.load()) {
                continue;
            }

            std::vector<vsomeip::byte_t> its_data(16, 0x11);
            its_data[0] = static_cast<vsomeip::byte_t>((seq >> 24) & 0xFF);
            its_data[1] = static_cast<vsomeip::byte_t>((seq >> 16) & 0xFF);
            its_data[2] = static_cast<vsomeip::byte_t>((seq >> 8) & 0xFF);
            its_data[3] = static_cast<vsomeip::byte_t>(seq & 0xFF);

            auto its_payload = vsomeip::runtime::get()->create_payload();
            its_payload->set_data(its_data);
            request_->set_payload(its_payload);
            app_->send(request_);

            const std::uint32_t sent = ++requests_sent_;
            if (sent <= 3 || (sent % 10) == 0) {
                std::cout << "[ids_client] REQUEST #" << std::dec << sent
                          << " (seq=" << seq << ")" << std::endl;
            }
            ++seq;
        }
    }

    std::shared_ptr<vsomeip::application> app_;
    std::shared_ptr<vsomeip::message> request_;

    std::uint32_t request_cycle_ms_;

    std::atomic<bool> running_{true};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> service_available_{false};
    std::atomic<bool> success_{false};
    std::atomic<std::uint32_t> responses_{0};
    std::atomic<std::uint32_t> notifications_{0};
    std::atomic<std::uint32_t> requests_sent_{0};

    std::mutex sender_mutex_;
    std::condition_variable sender_cv_;
    std::thread sender_thread_;
};

int main(int argc, char** argv) {
    std::uint32_t request_cycle_ms = DEFAULT_REQUEST_CYCLE_MS;
    std::uint32_t timeout_s = DEFAULT_TIMEOUT_S;

    for (int i = 1; i < argc; i++) {
        const std::string arg(argv[i]);
        if (arg == "--cycle" && i + 1 < argc) {
            request_cycle_ms = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--timeout" && i + 1 < argc) {
            timeout_s = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        }
    }

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    sigset_t its_signals;
    sigemptyset(&its_signals);
    sigaddset(&its_signals, SIGINT);
    sigaddset(&its_signals, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &its_signals, nullptr);
#endif

    ids_client client(request_cycle_ms);
    if (!client.init()) {
        return 1;
    }

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    // Thread de sinais: SIGINT/SIGTERM pedem parada limpa.
    std::thread signal_watcher([&client, &its_signals]() {
        int its_signal = 0;
        if (sigwait(&its_signals, &its_signal) == 0) {
            std::cout << "[ids_client] sinal " << its_signal << " recebido" << std::endl;
            client.request_stop();
        }
    });
#endif

    // Thread verificadora: declara sucesso/fracasso e encerra o aplicativo.
    std::thread checker([&client, timeout_s]() {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
        while (std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (client.responses() >= MIN_RESPONSES && client.notifications() >= MIN_NOTIFICATIONS) {
                client.mark_success();
                break;
            }
        }
        std::cout << "[ids_client] fim: respostas=" << std::dec << client.responses()
                  << " notificacoes=" << client.notifications()
                  << " sucesso=" << (client.success() ? "sim" : "nao") << std::endl;
        client.request_stop();
        // Acorda a thread de sinais (bloqueada em sigwait).
        ::kill(::getpid(), SIGTERM);
    });

    client.start(); // bloqueia ate app->stop()

    if (checker.joinable()) {
        checker.join();
    }
#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    if (signal_watcher.joinable()) {
        signal_watcher.join();
    }
#endif
    client.join_sender();

    const bool ok = client.success();
    std::cout << (ok ? "[ids_client] PASS" : "[ids_client] FAIL (timeout)")
              << " responses=" << client.responses()
              << " notifications=" << client.notifications() << std::endl;
    return ok ? 0 : 1;
}
