#!/usr/bin/env python3
"""
Minerva MCP Pentesting Framework
Main application entry point
"""

import os
from app import create_app

# Get configuration from environment or default to development
config_name = os.environ.get('FLASK_ENV', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    # Get host and port from environment
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     █████╗ ███████╗ ██████╗ ██╗███████╗                     ║
    ║    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝                     ║
    ║    ███████║█████╗  ██║  ███╗██║███████╗                     ║
    ║    ██╔══██║██╔══╝  ██║   ██║██║╚════██║                     ║
    ║    ██║  ██║███████╗╚██████╔╝██║███████║                     ║
    ║    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝                     ║
    ║                                                              ║
    ║    Minerva MCP Pentesting Framework                         ║
    ║    Agentic AI / MCP security testing                       ║
    ║                                                              ║
    ╠══════════════════════════════════════════════════════════════╣
    ║    Server: http://{host}:{port}                            ║
    ║    API Docs: http://{host}:{port}/api/v1                   ║
    ║    Environment: {config_name.upper()}                                  ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    app.run(host=host, port=port, debug=debug)
