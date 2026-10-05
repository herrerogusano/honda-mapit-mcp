# Phase 4 — Conversational Agent Integration

## Goal
Allow an agent to use the MCP naturally.

## Scope
Connect an MCP-capable language-model agent.

Target questions:
- How many km have I ridden this year?
- Which month did I use the bike most?
- What was my longest trip?
- Where is the bike?
- How does this year compare with last year?

## Principles
The agent should:
- choose tools rather than duplicate business logic;
- prefer analytics tools over processing large raw route lists;
- ground answers in tool outputs;
- not invent unavailable MAPIT capabilities.

## Evaluation
Create a fixed evaluation suite for:
- direct single-tool questions;
- multi-tool questions;
- comparisons;
- ambiguous periods;
- unavailable capabilities;
- errors.

## Exit criteria
The agent reliably selects suitable MCP tools and produces grounded answers.
