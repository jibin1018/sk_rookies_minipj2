# Scanner Refactoring Report

**Date**: 2026-01-04
**Author**: Antigravity Assistant

## 1. Overview
The Scanner component was refactored to address performance issues, overfitting to specific targets, and reporting granularity. This work follows the TDD methodology.

## 2. Key Changes

### 2.1 Web Crawler Implementation (Anti-Overfitting)
*   **Module**: `Scanner/web_crawler.py`
*   **Description**: Implemented a BFS-based crawler that dynamically discovers internal links and API endpoints (forms).
*   **Impact**: Removed hardcoded paths (e.g., `/api/auth/login`) from detection logic.

### 2.2 Parallel Processing Engine (Performance)
*   **Module**: `Scanner/scanner_engine.py`
*   **Description**: Integrated `ThreadPoolExecutor` with 10 worker threads.
*   **Impact**: Scan duration significantly reduced (Test benchmark: ~1.0s -> ~0.06s for mock tasks).

### 2.3 Granular Reporting
*   **Module**: `Scanner/modules/web/sqli.py` (and others via interface update)
*   **Description**: Updated `scan` interface to `scan_advanced` to accept crawled data.
*   **Impact**: 
    *   Reports now show exact "test counts" (payloads sent) rather than just "module counts".
    *   Vulnerabilities are broken down by subtype (e.g., `SQLi (Time-based)`, `SQLi (Error-based)`).

### 2.4 Compliance & Infrastructure Grouping
*   **Module**: `Scanner/infra_mapping.py`
*   **Description**: Added KISA guide codes (U-*, W-*, DB-*) to mapping definitions.
*   **Impact**: Output reports now align with standard compliance checklists.

### 2.5 Authenticated Scanning (New Feature)
*   **Modules**: `Scanner/app.py`, `Scanner/templates/index.html`, `Scanner/scanner_engine.py`
*   **Description**: Added UI and backend logic to inject Session Cookies and Custom Headers into the scanner.
*   **Impact**: Enables scanning of deep pages (e.g., `/dashboard`, `/mypage`) that require login.

## 3. Verification Results
*   `tests/test_crawler.py`: **PASS** (Link discovery & Form extraction verified)
*   `tests/test_engine_parallel.py`: **PASS** (Performance threshold met)

## 4. Pending Items
*   Update other detection modules to fully utilize `scan_advanced` interface.
*   Add more compliance patterns to `infra_mapping.py`.
