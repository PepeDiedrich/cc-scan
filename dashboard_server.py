#!/usr/bin/env python3
"""Serve the persisted cc-scan dashboard without starting a scan."""
import argparse

from src.runtime import DashboardServer, RuntimeMonitor


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve persisted cc-scan status and logs")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--state-file", default="scan-status.json")
    parser.add_argument("--log-file", default="scan.log")
    args = parser.parse_args()
    monitor = RuntimeMonitor(args.state_file, args.log_file, mark_running=False)
    dashboard = DashboardServer(monitor, args.host, args.port)
    print(f"Dashboard: http://{args.host}:{args.port}", flush=True)
    try:
        dashboard.server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        dashboard.server.server_close()


if __name__ == "__main__":
    main()
