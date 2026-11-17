// SPDX-License-Identifier: MIT
// Source-only candidate. Generated wrappers and execution evidence stay in the build tree.
#include <wayland-client.h>
#include <wayland-server-core.h>
#include "qwayland-desktop-probe.h"
#include "qwayland-server-desktop-probe.h"

#include <QString>
#include <QtGlobal>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace {
static_assert(QT_VERSION == QT_VERSION_CHECK(6, 12, 0), "Qt6.12.0 headers required");
constexpr uint32_t serial = 0x612a51;
QString payload() { return QStringLiteral("Qt6.12 generated echo \u03bb"); }

// Qt6.12 qtwaylandscanner.cpp:518,569-590 emits these constructors/callbacks.
class EchoServer final : public QtWaylandServer::qt612_desktop_probe_v1 {
public:
    explicit EchoServer(wl_display *display) : qt612_desktop_probe_v1(display, 1) {}
    unsigned requests = 0;
    bool valid = true;
private:
    void qt612_desktop_probe_v1_echo(Resource *resource, uint32_t value, const QString &text) override
    {
        valid = ++requests == 1 && value == serial && text == payload();
        if (valid)
            send_echoed(resource->handle, value, text);
    }
};

// Scanner string arguments become const QString&; client events are virtual.
class EchoClient final : public QtWayland::qt612_desktop_probe_v1 {
public:
    ~EchoClient() override
    {
        if (isInitialized())
            wl_proxy_destroy(reinterpret_cast<wl_proxy *>(object()));
    }
    unsigned replies = 0;
    bool valid = true;
    uint32_t global = 0;
private:
    void qt612_desktop_probe_v1_echoed(uint32_t value, const QString &text) override
    {
        valid = ++replies == 1 && value == serial && text == payload();
    }
};

void announced(void *data, wl_registry *registry, uint32_t name, const char *interface, uint32_t version)
{
    if (std::strcmp(interface, "qt612_desktop_probe_v1") != 0)
        return;
    auto &client = *static_cast<EchoClient *>(data);
    if (client.isInitialized() || version != 1) {
        client.valid = false;
        return;
    }
    auto *object = static_cast<::qt612_desktop_probe_v1 *>(
        wl_registry_bind(registry, name, EchoClient::interface(), 1));
    if (!object) {
        client.valid = false;
        return;
    }
    client.global = name;
    client.init(object);
    client.echo(serial, payload());
}

void removed(void *data, wl_registry *, uint32_t name)
{
    auto &client = *static_cast<EchoClient *>(data);
    if (name == client.global)
        client.valid = false;
}

bool exchange(wl_display *server, wl_display *client, EchoServer &service, EchoClient &endpoint)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    auto *loop = wl_display_get_event_loop(server);
    if (!loop)
        return false;
    while (std::chrono::steady_clock::now() < deadline && service.valid && endpoint.valid) {
        if (wl_display_dispatch_pending(client) < 0)
            return false;
        if (endpoint.replies)
            return endpoint.valid && service.valid && endpoint.replies == 1
                && service.requests == 1 && wl_display_get_error(client) == 0;
        const int flushed = wl_display_flush(client);
        const bool writePending = flushed < 0 && errno == EAGAIN;
        if (flushed < 0 && !writePending)
            return false;
        if (wl_event_loop_dispatch(loop, 0) < 0)
            return false;
        wl_display_flush_clients(server);
        if (wl_display_prepare_read(client) != 0)
            continue; // Pending callbacks are dispatched on the next bounded iteration.
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) {
            wl_display_cancel_read(client);
            return false;
        }
        pollfd input{wl_display_get_fd(client), static_cast<short>(POLLIN | (writePending ? POLLOUT : 0)), 0};
        const int ready = poll(&input, 1, static_cast<int>(std::min<int64_t>(left, 5)));
        const int pollError = errno;
        if (ready > 0 && (input.revents & POLLIN)) {
            if (wl_display_read_events(client) < 0)
                return false;
        } else {
            wl_display_cancel_read(client);
        }
        if ((ready < 0 && pollError != EINTR) || (input.revents & (POLLERR | POLLHUP | POLLNVAL)))
            return false;
    }
    return false;
}

struct ServerClients {
    wl_display *display;
    ~ServerClients() { wl_display_destroy_clients(display); }
};

struct SocketPair {
    int fd[2] = {-1, -1};
    ~SocketPair() { for (int descriptor : fd) if (descriptor >= 0) close(descriptor); }
};
} // namespace

int main()
{
    if (std::strcmp(qVersion(), "6.12.0") != 0) {
        std::fputs("FAIL_QT612_PROTOCOL_CORE_VERSION\n", stderr);
        return 1;
    }
    // No QGuiApplication, named Wayland socket, display connection or GPU is created.
    std::unique_ptr<wl_display, decltype(&wl_display_destroy)> server(wl_display_create(), wl_display_destroy);
    if (!server)
        return 1;
    EchoServer service(server.get());
    if (!service.isGlobal())
        return 1;
    ServerClients clients{server.get()}; // Retire resources before the generated server wrapper.
    SocketPair sockets;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets.fd) < 0)
        return 1;
    // Server API consumes this endpoint only on success; retain failure cleanup.
    if (!wl_client_create(server.get(), sockets.fd[0]))
        return 1;
    sockets.fd[0] = -1;
    // Client connect_to_fd consumes its endpoint on both success and failure.
    std::unique_ptr<wl_display, decltype(&wl_display_disconnect)> client(
        wl_display_connect_to_fd(std::exchange(sockets.fd[1], -1)), wl_display_disconnect);
    if (!client)
        return 1;
    EchoClient endpoint;
    std::unique_ptr<wl_registry, decltype(&wl_registry_destroy)> registry(
        wl_display_get_registry(client.get()), wl_registry_destroy);
    const wl_registry_listener listener{announced, removed};
    if (!registry || wl_registry_add_listener(registry.get(), &listener, &endpoint) != 0)
        return 1;
    if (!exchange(server.get(), client.get(), service, endpoint)) {
        std::fputs("FAIL_QT612_GENERATED_ANONYMOUS_PROTOCOL\n", stderr);
        return 1;
    }
    std::puts("PASS_QT612_GENERATED_ANONYMOUS_PROTOCOL");
    return 0;
}
