# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Workflow Orchestration
### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update 'tasks/lessons.md' with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- Use SOLID principles, avoid create god class file
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests -> then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

## Task Management
1. Plan First: Write plan to 'tasks/todo.md' with checkable items
2. Verify Plan: Check in before starting implementation
3. Track Progress: Mark items complete as you go
4. Explain Changes: High-level summary at each step
5. Document Results: Add review to 'tasks/todo.md'
6. Capture Lessons: Update 'tasks/lessons.md' after corrections

## Core Principles
- Simplicity First: Make every change as simple as possible. Impact minimal code.
- No Laziness: Find root causes. No temporary fixes. Senior developer standards.
- Minimal Impact: Changes should only touch what's necessary. Avoid introducing bugs.

When you need to call tools from the shell, use this rubric:

- Find files by file name: `fd`
- Find files with path name: `fd -p <file-path>`
- List files in a directory: `fd . <directory>`
- Find files with extension and pattern: `fd -e <extension> <pattern>`
- Find Text: `rg` (ripgrep)
- Find Code Structure: `ast-grep`
    - Default to TypeScript when in TS/TSX repos:
        - `.ts` → `ast-grep --lang ts -p '<pattern>'`
        - `.tsx` (React) → `ast-grep --lang tsx -p '<pattern>'`
    - Other common languages:
        - Python → `ast-grep --lang python -p '<pattern>'`
        - Bash → `ast-grep --lang bash -p '<pattern>'`
        - JavaScript → `ast-grep --lang js -p '<pattern>'`
        - Rust → `ast-grep --lang rust -p '<pattern>'`
        - JSON → `ast-grep --lang json -p '<pattern>'`
- Select among matches: pipe to `fzf`
- JSON: `jq`
- YAML/XML: `yq`

## Project Overview

eGuard Agent is a production-grade **Endpoint Detection and Response (EDR)** agent. Rust workspace (13 crates) with Zig (eBPF probes + ASM acceleration) and Go (server-side, in separate repo at `/home/dimas/fe_eguard/`). Design doc: `/home/dimas/fe_eguard/docs/eguard-agent-design.md`.

VM Test: 
ssh eguard@157.10.160.90, database mysql, root:Eguard123, webgui admin:Eguard123
