# Payload Model - Synthetic CAN-style Signals

This document defines the synthetic payload model used for the Normal datasets
(Normal_RR, Normal_NEpc, Normal_NEc) in the someip-ids project.

The model is designed based on real CAN bus signals found in automotive vehicles
(e.g. driver assistance systems), but implemented using fixed-size SOME/IP
packets as specified by the vsomeip 3.7.6 implementation.

## 1. Payload Format

Payload sizes by message kind (fixed, no dynamic fields):

| Kind | Size | Content |
|------|------|---------|
| ECHO request (Normal_RR) | 16 bytes | bytes 0-3 = sequence counter (BE), bytes 4-15 = 0x11 |
| SetMode request (NEpc/NEc) | 2 bytes | byte 0 = mode index (0-3), byte 1 = 0x00 |
| Response (any method) | 4 bytes | byte 0 = echo of request byte 0, byte 1 = current server mode, bytes 2-3 = 0x22 |
| Notification (event 0x8001) | 16 bytes | signal layout below |

The 16-byte request/notification layout is the shape used by the existing
Fase 1 implementation.

```
Offset  Size  Field
0-1     2     Speed (uint16 BE)           - km/h or m/s, 0-65535
2-3     2     SteeringAngle (int16 BE)    - -32768 to 32767, signed
4       1     GearShift (uint8)           - 0=Neutral, 1=1st, 2=2nd, 3=3rd, 4=4th, 5=5th, 6=6th
5       1     Brake (uint8)               - 0=Released, 1=Pressed
6       1     ACCState (uint8)            - 0=Off, 1=Resume, 2=Set, 3=Coast, 4=Cancel
7       1     TurnSignal (uint8)          - 0=Off, 1=Left, 2=Right, 3=Hazard
8-15    8     Reserved (always 0x00)      - not populated (DistanceLead, OcclusionLevel,
                                            RadarQuality, Checksum stay 0)
```

**Note:** Only bytes 0-7 are actively varied during dataset generation.
Bytes 8-15 are always 0x00. This keeps the payload size consistent with the
existing `ids_server.cpp` NOTIFICATION format while providing 6 distinct
CAN-style signals.

## 2. Signal Definitions

| Signal          | Bits (within 16-byte payload) | Type        | Range                                | Variation Pattern |
|-----------------|-------------------------------|-------------|--------------------------------------|-------------------|
| Speed           | 0-15                          | uint16 BE   | 0 - 65535                            | Sinusoidal, ±5 units/cycle |
| SteeringAngle   | 16-31                         | int16 BE    | -32768 to 32767                      | Sinusoidal, ±10 units/cycle |
| GearShift       | 32-35 (bits within byte 4)   | enum        | 0=Neutral, 1=1st, 2=2nd, 3=3rd, 4=4th, 5=5th, 6=6th | ±1 random step per notification, clamped to the mode's gear bounds |
| Brake           | 36 (bit 0 of byte 5)         | bool        | 0=Released, 1=Pressed                | Toggles on hard braking |
| ACCState        | 39-41 (bits 3-5 of byte 6)   | FSM         | 0=Off, 1=Resume, 2=Set, 3=Coast, 4=Cycle | Transitions on mode change |
| TurnSignal      | 44-46 (bits 2-4 of byte 7)   | enum        | 0=Off, 1=Left, 2=Right, 3=Hazard     | Cycles Left↔Right periodically |

**Bit numbering convention:** Bit 0 is the MSB of byte 0, bit 15 is the LSB of byte 1,
bit 16 is the MSB of byte 2, etc. This is consistent with big-endian SOME/IP payloads.

## 3. Server State Machine ("Mode")

The server maintains an internal **`drive_mode`** state that determines the value
ranges and variation patterns of the signals. The mode is changed by a
`SetMode` Request (Normal_NEpc: service 0x1235, instance 0x0001, method 0x0002;
Normal_NEc: service 0x1236, instance 0x0001, method 0x0003; Normal_RR has no
SetMode) or automatically every `mode_cycle` notifications (default 50).

### Modes

| Mode | Index | Speed Range          | Steering Range       | Gear Pattern            | ACC Behavior      | TurnSignal      |
|------|-------|----------------------|----------------------|-------------------------|-------------------|-----------------|
| Mode A | 0     | 20000 - 40000        | -1000 to 1000        | 1-3 (constant)          | Resume (1)        | Off (0)         |
| Mode B | 1     | 10000 - 30000        | -2000 to 2000        | 1-4 (rotating)          | Coast (3)         | Left (1)        |
| Mode C | 2     | 30000 - 50000        | -500 to 500          | 2-5 (rotating)          | Set (2)           | Right (2)       |
| Mode D | 3     | 25000 - 45000        | -1500 to 1500        | 3-5 (alternating)       | Resume (1)        | Hazard (3)      |

**Transitions:**
- `SetMode` request (method 0x0002 on 0x1235 / 0x0003 on 0x1236) → **sets** the
  mode index to the value in request byte 0 (clamped to 0-3); the client rotates
  the index A→B→C→D across successive SetMode requests
- Independently, the server advances the mode automatically every `mode_cycle`
  notifications (default 50, `--mode-cycle`); `SetMode` resets that counter
- Each mode change alters **at least two** signal ranges (as required by the prompt)
- The mode wraps: D → A → B → C → D

## 4. Signal Generation Patterns

### Speed (bytes 0-1)
- Updated every `notify_cycle_ms` (YAML: 500 ms Normal_RR, 10 ms Normal_NEpc/NEc)
- Value = `base_speed + amplitude * sin(2 * pi * t / period)`
- `base_speed` depends on current mode (see table above)
- `amplitude` = 3000 (half the mode range)
- `period` = 20 cycles per dataset run (slow variation)
- **Jitter:** ±2 units added randomly each update

### SteeringAngle (bytes 2-3)
- Same sinusoidal pattern as Speed
- `base_steering` depends on current mode
- `amplitude` = 1000
- `period` = 15 cycles per dataset run
- **Inversion:** Sign inverts when GearShift changes from 1st to 2nd gear

### GearShift (byte 4)
- ±1 random step per notification (~12% chance), clamped to the mode's gear
  bounds (mode change via SetMode/auto-advance moves the bounds)
- The gear never jumps outside the current mode's range

### Brake (byte 5, bit 0)
- Toggles randomly with probability 0.02 per notification cycle
- When Brake=1, ACCState forced to 0 (Off) and Speed reduction applied

### ACCState (bits 3-5 of byte 6)
- Set to the mode default each notification (A: Resume, B: Coast, C: Set, D: Resume)
- When Brake=1, ACCState = 0 (Off) regardless of mode

### TurnSignal (bits 2-4 of byte 7)
- Set to the mode default each notification (A: Off, B: Left, C: Right, D: Hazard)
- Hazard mode: Left and Right alternate rapidly (every 3 notifications)

## 5. Request/Response Model

### ECHO Request (Client → Server, Normal_RR)
- **Service:** 0x1234
- **Instance:** 0x0001
- **Method:** 0x0001
- **Payload:** 16 bytes — bytes 0-3 = sequence counter (BE), bytes 4-15 = 0x11
- **Response:** 4 bytes (below), return code E_OK or E_NOT_OK (NG events)

### SetMode Request (Client → Server, Normal_NEpc / Normal_NEc)
- **Service:** 0x1235 (Normal_NEpc) or 0x1236 (Normal_NEc)
- **Instance:** 0x0001
- **Method:** 0x0002 (Normal_NEpc) or 0x0003 (Normal_NEc)
- **Payload:** 2 bytes
  - Byte 0: New mode index (0-3)
  - Byte 1: Reserved (0x00)
- **Response:** 4 bytes — byte 0 echoes the request byte 0, byte 1 = current
  server mode, bytes 2-3 = 0x22 filler

### Effect of SetMode
- Immediately **sets** the internal `drive_mode` index (clamped to 0-3) and
  resets the auto-advance notification counter
- Alters the value ranges and patterns for **at least two** signals (per Mode table)
- Resets some signal values to mode-appropriate baselines
- Generates a notification event with updated payload to inform all subscribers

## 6. Dataset Generation Rules

During the creation of each Normal dataset, the following rules apply:

1. **Initial state:** Mode A is active at dataset start
2. **SetMode occurrences:** a SetMode request is sent every `K` request cycles
   (Normal_NEpc: K = 50 → every 1 s at 20 ms; Normal_NEc: K = 100 → every 5 s
   at 50 ms; YAML `setmode_every_cycles`). The payload's mode index rotates
   A→B→C→D. Normal_RR sends ECHO requests only (no SetMode), every 100 ms.
   The server *also* advances the mode every 50 notifications (`mode_cycle`)
3. **Request/Response:** Interleaved with notifications; each request increments a sequence counter
4. **NG (No-Go) events:** a fraction `p_ng` of Request/Response exchanges return
   SOME/IP Return Code `0x01` (E_NOT_OK) instead of `0x00` (E_OK), drawn from a
   deterministic RNG seeded with `seed + service_id + session_id`:
   p_ng = 0.05 (Normal_RR), 0.02 (Normal_NEpc), 0.01 (Normal_NEc). These are
   logged but do not alter the server state
5. **Brake events:** Random toggles as described above, affecting ACCState and Speed
6. **TurnSignal cycles:** follows the mode default (Hazard alternates Left/Right
   every 3 notifications in Mode D)

## 7. Summary of Changes per Mode

| Signal         | Mode A → B     | Mode B → C     | Mode C → D     | Mode D → A     |
|----------------|----------------|----------------|----------------|----------------|
| **Speed base** | 20000 → 10000  | 10000 → 30000  | 30000 → 25000  | 25000 → 20000  |
| **Steering base** | -1000 → -2000  | -2000 → -500   | -500 → -1500   | -1500 → -1000  |
| **Gear pattern**| 1-3 → 1-4      | 1-4 → 2-5      | 2-5 → 3-5      | 3-5 → 3-5 (hold) |
| **ACC default**| Resume(1) → Coast(3) | Coast(3) → Set(2) | Set(2) → Resume(1) | Resume(1) → hold |
| **TurnSignal** | Off(0) → Left(1) | Left(1) → Right(2) | Right(2) → Hazard(3) | Hazard(3) → Off(0) |

## 8. Service / Method / Port Map

| Dataset | Service ID | Instance | Method (request = response) | Event | Eventgroup | UDP port |
|---------|-----------|----------|-----------------------------|-------|------------|----------|
| Normal_RR | 0x1234 | 0x0001 | ECHO 0x0001 | — | — | 30509 |
| Normal_NEpc | 0x1235 | 0x0001 | SetMode 0x0002 | 0x8001 | 0x0001 | 30510 |
| Normal_NEc | 0x1236 | 0x0001 | SetMode 0x0003 | 0x8001 | 0x0001 | 30511 |
| Service Discovery (all) | 0xFFFF | — | — | — | — | 30490, multicast 224.224.224.245 |

All services are UDP (`unreliable` ports in `config/ecu5/ids_dataset.json`);
the notification payload/eventgroup are identical across the three services.

**Reuse from Fase 1:** Fase 1 defined Serviço A = 0x1234.0001 (ECHO method
0x0001) and Serviço B = 0x1235.0001 (TELEMETRY event 0x8001, eventgroup 0x0001).
Normal_RR reuses Serviço A unchanged. Normal_NEpc reuses the Fase 1 service
**ID** 0x1235 with a **new method** 0x0002 (SetMode); the event 0x8001 was
exclusive to the Fase 1 service 0x1235 and is now carried by each Fase 2
service (0x1234 also offers it, for the rare RR notification). Normal_NEc adds
the new service 0x1236.