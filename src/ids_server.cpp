// =============================================================================
// ids_server.cpp -- servidor SOME/IP (roda em ecu5, IP 192.168.2.4)
//
//  * Servico A (0x1234.0001): metodo ECHO (0x0001)  -> Request/Response.
//  * Servico B (0x1235.0001): evento TELEMETRY (0x8001) no eventgroup 0x0001,
//                             notificado periodicamente -> Notification Events.
//
// O processo fica no ar ate receber SIGINT/SIGTERM (parada limpa pelo
// smoke test / docker stop).
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
#include <vector>

#if defined(__linux__)
#include <pthread.h>
#endif

#include "ids.hpp"

class ids_server {
public:
    explicit ids_server(std::uint32_t _notify_cycle_ms)
        : app_(vsomeip::runtime::get()->create_application(ids::APP_SERVER)),
          notify_cycle_ms_(_notify_cycle_ms),
          notify_thread_(&ids_server::notify_loop, this) {}

    bool init() {
        if (!app_->init()) {
            std::cerr << "[ids_server] app->init() falhou" << std::endl;
            return false;
        }

        app_->register_state_handler([this](vsomeip::state_type_e _state) { on_state(_state); });

        app_->register_message_handler(
                ids::SERVICE_REQRESP, ids::INSTANCE, ids::METHOD_ECHO,
                [this](const std::shared_ptr<vsomeip::message>& _msg) { on_echo(_msg); });

        // O evento e publicado como EVENT puro (nao field) -- ver config/README.md.
        std::set<vsomeip::eventgroup_t> its_groups;
        its_groups.insert(ids::EVENTGROUP_TELEMETRY);
        app_->offer_event(ids::SERVICE_EVENTS, ids::INSTANCE, ids::EVENT_TELEMETRY, its_groups,
                          vsomeip::event_type_e::ET_EVENT, std::chrono::milliseconds::zero(),
                          false /*change_resets_cycle*/, true /*update_on_change*/, nullptr,
                          vsomeip::reliability_type_e::RT_UNRELIABLE);

        std::cout << "[ids_server] init ok ("
                  << std::hex << std::setfill('0')
                  << std::setw(4) << ids::SERVICE_REQRESP << "."
                  << std::setw(4) << ids::INSTANCE << " method "
                  << std::setw(4) << ids::METHOD_ECHO << " | "
                  << std::setw(4) << ids::SERVICE_EVENTS << " event "
                  << std::setw(4) << ids::EVENT_TELEMETRY << ")"
                  << std::dec << std::endl;
        return true;
    }

    void start() { app_->start(); }

    void stop() {
        running_ = false;
        notify_cv_.notify_all();
        if (notify_thread_.joinable()) {
            notify_thread_.join();
        }
        app_->clear_all_handler();
        app_->stop_offer_service(ids::SERVICE_REQRESP, ids::INSTANCE);
        app_->stop_offer_service(ids::SERVICE_EVENTS, ids::INSTANCE);
        app_->stop();
    }

private:
    void on_state(vsomeip::state_type_e _state) {
        if (_state == vsomeip::state_type_e::ST_REGISTERED) {
            app_->offer_service(ids::SERVICE_REQRESP, ids::INSTANCE);
            app_->offer_service(ids::SERVICE_EVENTS, ids::INSTANCE);
            registered_ = true;
            {
                std::lock_guard<std::mutex> lock(notify_mutex_);
                notify_cv_.notify_all();
            }
            std::cout << "[ids_server] registrado; servicos 0x1234 e 0x1235 em oferta"
                      << std::endl;
        } else {
            registered_ = false;
            std::cout << "[ids_server] deregistrado" << std::endl;
        }
    }

    void on_echo(const std::shared_ptr<vsomeip::message>& _request) {
        auto its_response = vsomeip::runtime::get()->create_response(_request);

        std::vector<vsomeip::byte_t> its_data(32, 0x22);
        const std::uint32_t seq = request_counter_.load();
        its_data[0] = static_cast<vsomeip::byte_t>((seq >> 24) & 0xFF);
        its_data[1] = static_cast<vsomeip::byte_t>((seq >> 16) & 0xFF);
        its_data[2] = static_cast<vsomeip::byte_t>((seq >> 8) & 0xFF);
        its_data[3] = static_cast<vsomeip::byte_t>(seq & 0xFF);

        auto its_payload = vsomeip::runtime::get()->create_payload();
        its_payload->set_data(its_data);
        its_response->set_payload(its_payload);
        app_->send(its_response);

        const std::uint32_t n = ++request_counter_;
        std::cout << "[ids_server] ECHO request #" << std::dec << n
                  << " respondido (client=0x" << std::hex << std::setfill('0')
                  << std::setw(4) << _request->get_client()
                  << " session=0x" << std::setw(4) << _request->get_session()
                  << ")" << std::dec << std::endl;
    }

    void notify_loop() {
        std::uint32_t counter = 0;
        while (running_) {
            {
                std::unique_lock<std::mutex> lock(notify_mutex_);
                notify_cv_.wait(lock, [this] { return !running_ || registered_.load(); });
            }
            if (!running_) {
                break;
            }

            std::vector<vsomeip::byte_t> its_data(12, 0x33);
            its_data[0] = static_cast<vsomeip::byte_t>((counter >> 24) & 0xFF);
            its_data[1] = static_cast<vsomeip::byte_t>((counter >> 16) & 0xFF);
            its_data[2] = static_cast<vsomeip::byte_t>((counter >> 8) & 0xFF);
            its_data[3] = static_cast<vsomeip::byte_t>(counter & 0xFF);

            auto its_payload = vsomeip::runtime::get()->create_payload();
            its_payload->set_data(its_data);
            app_->notify(ids::SERVICE_EVENTS, ids::INSTANCE, ids::EVENT_TELEMETRY, its_payload);

            ++counter;
            if ((counter % 10) == 0) {
                std::cout << "[ids_server] notify TELEMETRY #" << std::dec << counter << std::endl;
            }

            std::unique_lock<std::mutex> lock(notify_mutex_);
            notify_cv_.wait_for(lock, std::chrono::milliseconds(notify_cycle_ms_),
                                [this] { return !running_; });
        }
    }

    std::shared_ptr<vsomeip::application> app_;

    std::uint32_t notify_cycle_ms_;
    std::atomic<bool> registered_{false};
    std::atomic<bool> running_{true};
    std::atomic<std::uint32_t> request_counter_{0};

    std::mutex notify_mutex_;
    std::condition_variable notify_cv_;
    std::thread notify_thread_;
};

int main(int argc, char** argv) {
    std::uint32_t cycle_ms = 500;

    const std::string cycle_arg("--cycle");
    for (int i = 1; i < argc; i++) {
        if (cycle_arg == argv[i] && i + 1 < argc) {
            ++i;
            cycle_ms = static_cast<std::uint32_t>(std::stoul(argv[i]));
        }
    }

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    sigset_t its_signals;
    sigemptyset(&its_signals);
    sigaddset(&its_signals, SIGINT);
    sigaddset(&its_signals, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &its_signals, nullptr);
#endif

    ids_server server(cycle_ms);
    if (!server.init()) {
        return 1;
    }

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    std::thread signal_watcher([&server, &its_signals]() {
        int its_signal = 0;
        sigwait(&its_signals, &its_signal);
        server.stop();
    });
#endif

    server.start();

#ifndef VSOMEIP_ENABLE_SIGNAL_HANDLING
    if (signal_watcher.joinable()) {
        signal_watcher.join();
    }
#endif
    std::cout << "[ids_server] encerrado" << std::endl;
    return 0;
}
