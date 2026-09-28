# Phase 1 — MCP Core & Read-Only Tools

## Goal
Create the first usable MCP server on top of the existing MAPIT client.

## Architecture
```text
MCP Tool
   ↓
Application Service
   ↓
MapitClient
   ↓
MAPIT
```

The MCP layer must stay thin. Business logic belongs in services.

## Scope
Implement:
- MCP server bootstrap;
- tool registration;
- stable input/output schemas;
- service layer;
- error mapping;
- read-only guarantees;
- MCP contract tests.

## Initial tools

### `get_vehicle_status`
Return current operational state:
- status;
- current/last speed;
- battery;
- voltage when available;
- last communication;
- last coordinate update;
- current/last known position metadata;
- GPS accuracy;
- odometer when available.

### `get_vehicle_details`
Return mostly static information:
- model;
- registration;
- VIN;
- mileage/odometer;
- product;
- plan;
- dealer/contact metadata when present.

### `list_routes(from, to)`
Return normalized routes for a requested period.

The service layer handles:
- date validation;
- safe monthly window splitting;
- MAPIT calls;
- route normalization;
- deduplication.

### `get_route_detail(route_id)`
Return normalized detail for one route, including available GeoJSON and route metadata.

### `get_distance(from, to)`
Return total travelled distance for a period.

The MCP tool delegates to the route/analytics service.

### `compare_distance_periods(period_a, period_b)`
Return:
- distance A;
- distance B;
- absolute difference;
- percentage difference when valid.

## Out of scope
- conversational agent;
- Telegram;
- database;
- persistent realtime listener;
- Home Assistant;
- write operations.

## Exit criteria
- MCP server starts reliably;
- all tools work through MCP;
- services reuse `MapitClient`;
- business logic is not duplicated in MCP;
- read-only behavior is enforced;
- tests and CI are green;
- contracts are documented.
