# =============================================================================
# automotive-ids / SOMEIP-IDS
#
# Imagem unica usada pelos 5 ECUs (ecu1..ecu5).
#
#   * toolchain C++ (gcc, cmake, boost) para compilar o vsomeip a partir do
#     codigo-fonte oficial COVESA/vsomeip;
#   * vsomeip 3.7.6 (tag fixa, ver ARG VSOMEIP_VERSION) instalado em /usr/local;
#   * aplicacoes de exemplo do laboratorio (ids_client / ids_server);
#   * somente as ferramentas de captura/diagnose: tcpdump, iproute2, iptables,
#     smcroute (roteamento de multicast SOME/IP-SD), ping.
#
# NAO instala Wireshark/tshark (sem GUI, sem dependencias pesadas): a leitura
# programatica dos pcaps e feita fora do container com scapy/Python.
# =============================================================================

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
# Versao fixa do vsomeip para reprodutibilidade (tag do repositorio COVESA/vsomeip).
ARG VSOMEIP_VERSION=3.7.6

# --- dependencias de build + ferramentas de rede/captura ---------------------
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        iproute2 \
        iptables \
        iputils-ping \
        libboost-filesystem-dev \
        libboost-system-dev \
        pkg-config \
        procps \
        smcroute \
        tcpdump \
 && rm -rf /var/lib/apt/lists/*

# --- compila o vsomeip a partir do codigo-fonte oficial -----------------------
# -DVSOMEIP_INSTALL_ROUTINGMANAGERD=ON instala o daemon "routingmanagerd".
RUN git clone --depth 1 --branch "${VSOMEIP_VERSION}" \
        https://github.com/COVESA/vsomeip.git /tmp/vsomeip \
 && cmake -S /tmp/vsomeip -B /tmp/vsomeip/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DVSOMEIP_INSTALL_ROUTINGMANAGERD=ON \
 && cmake --build /tmp/vsomeip/build -j"$(nproc)" \
 && cmake --install /tmp/vsomeip/build \
 && ldconfig \
 && rm -rf /tmp/vsomeip

# --- aplicacoes de teste (cliente/servidor SOME/IP do laboratorio) -----------
COPY src/ /opt/ids/src/
RUN cmake -S /opt/ids/src -B /opt/ids/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
 && cmake --build /opt/ids/build -j"$(nproc)" \
 && cmake --install /opt/ids/build \
 && ldconfig \
 && rm -rf /opt/ids/build

# --- scripts de arranque do ECU ----------------------------------------------
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && mkdir -p /pcaps /logs

WORKDIR /work

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
