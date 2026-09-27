// =============================================================================
// ids.hpp -- Identificadores SOME/IP usados no laboratorio someip-ids.
//
// IMPORTANTE: estes IDs sao ficticios (nao vem de nenhum padrao de fabricante)
// mas estao FIXADOS aqui e em config/README.md para serem reutilizados nas
// proximas fases do projeto (captura, extracao de features, treino do IDS).
//
// Se algum ID mudar, mudar TAMBEM em config/ecu1/ids.json e config/ecu5/ids.json.
// =============================================================================
#pragma once

#include <cstdint>

#include <vsomeip/vsomeip.hpp>

namespace ids {

// --- ECU / aplicacao ---------------------------------------------------------
// (nomes de aplicacao devem casar com "applications" nos JSONs de config)
inline constexpr const char* APP_CLIENT = "ids-client";  // roda em ecu1
inline constexpr const char* APP_SERVER = "ids-server";  // roda em ecu5
// O daemon de roteamento se chama "routingmanagerd" (nome fixo do vsomeipd).

// --- Servico A: Request/Response (cliente ecu1 -> servidor ecu5) -------------
inline constexpr vsomeip::service_t  SERVICE_REQRESP  = 0x1234;
inline constexpr vsomeip::instance_t INSTANCE         = 0x0001;
inline constexpr vsomeip::method_t   METHOD_ECHO      = 0x0001;

// --- Servico B: Notification Events (servidor ecu5 publica, ecu1 assina) -----
inline constexpr vsomeip::service_t     SERVICE_EVENTS    = 0x1235;
inline constexpr vsomeip::event_t       EVENT_TELEMETRY   = 0x8001;
inline constexpr vsomeip::eventgroup_t  EVENTGROUP_TELEMETRY = 0x0001;

// --- Portas UDP --------------------------------------------------------------
inline constexpr std::uint16_t PORT_SD          = 30490; // SOME/IP-SD
inline constexpr std::uint16_t PORT_SERVICE_A   = 30509; // endpoint UDP do 0x1234
inline constexpr std::uint16_t PORT_SERVICE_B   = 30510; // endpoint UDP do 0x1235
inline constexpr std::uint16_t PORT_SD_MULTICAST = 30490;

// --- Grupo multicast SOME/IP-SD (padrao do protocolo) ------------------------
inline constexpr const char* SD_MULTICAST = "224.224.224.245";

// --- Formato dos payloads (documentado para as fases seguintes do IDS) -------
// REQUEST   (16 bytes): [0..3]  uint32 BE = sequencia do pedido
//                       [4..15] 0x11
// RESPONSE  (32 bytes): [0..3]  uint32 BE = eco da sequencia
//                       [4..31] 0x22
// NOTIFICATION (12 bytes): [0..3] uint32 BE = contador de notificacao
//                          [4..11] 0x33

} // namespace ids
