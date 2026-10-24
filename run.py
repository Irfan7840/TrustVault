import os
import sys
from trustvault import create_app

env_name = os.environ.get("FLASK_ENV", "development")
app = create_app(env_name)

if __name__ == "__main__":
    # In public/tunnel environments, never enable Werkzeug interactive debugger
    # Respect PORT environment variable for cloud hosting and tunnels
    port = int(os.environ.get("PORT", 5000))
    # Listen on 0.0.0.0 so that local network, Pinggy, and tunnels can connect cleanly
    host = os.environ.get("HOST", "0.0.0.0")
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")

    print(f" * TrustVault starting on http://localhost:{port} (host={host})")
    print(f" * Environment: {env_name} | Debug mode: {debug_mode}")
    try:
        app.run(host=host, port=port, debug=debug_mode)
    except OSError as e:
        if "Address already in use" in str(e) or "10048" in str(e):
            print(f"\n[ERROR] Port {port} is already in use by another process.")
            print(f"Please stop the conflicting process or run with a different port:")
            print(f"  $env:PORT=5001; python run.py\n")
        else:
            print(f"\n[ERROR] Failed to start server: {e}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error during startup: {e}\n")
        sys.exit(1)
