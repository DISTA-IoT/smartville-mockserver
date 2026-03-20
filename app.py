# This file is part of the "Smartville" project.
# Copyright (c) 2024 University of Insubria
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0
# For the full text of the license, visit:
# https://www.apache.org/licenses/LICENSE-2.0

# Smartville is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# Apache License 2.0 for more details.

# You should have received a copy of the Apache License 2.0
# along with Smartville. If not, see <https://www.apache.org/licenses/LICENSE-2.0>.

# Additional licensing information for third-party dependencies
# used in this file can be found in the accompanying `NOTICE` file.

import logging
from fastapi import FastAPI
import uvicorn
import os
from scapy.all import *
import netifaces as ni
from threading import Lock
import time
import subprocess



# Global variables for process management
SOURCE_IP = None
SOURCE_MAC = None
TARGET_IP = None
IFACE_NAME = 'eth0'
PATTERN_TO_REPLAY = None
PREPROCESSED = None
SPEED_MULTIPLIER = None
HEALTH_MONITORING = None
KAFKA_ENDPOINT = None
HEALTH_PROBE_FREQUENCY = None


health_monitor = None
kafka_msg_producer = None
healt_probes_count = 0
stop_flag = True
stop_flag_lock = Lock()
current_replay_process: Optional[subprocess.Popen] = None
replay_thread = None
checker_thread = None
health_thread = None
rewriting = False

logger = logging.getLogger("honeypot_server")
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api.log"),
        logging.StreamHandler()
    ]
)


app = FastAPI(title="Mockserver Server API", description="API for simulating honeypots")

def get_static_source_ip_address(interface=IFACE_NAME):
    try:
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        return ip
    except ValueError:
        return "Interface not found"


@app.get("/echo")
def echo_target():
    """
    Application-layer echo.
    Simulates a lightweight microservice response.
    """
    return {"status": "ok", "timestamp": time.time()}



if __name__ == "__main__":
    logger.info("Starting MockApp FastAPI server")
    
    try:
        port = int(os.environ.get("SERVER_PORT"))
    except Exception as e:
        print(f"Error parsing SERVER_PORT env var: {e}")
        assert False
    try:
        SOURCE_IP = get_static_source_ip_address()
    except Exception as e:
        print(f"Error obtaining SOURCE_IP env var: {e}")
        assert False

    uvicorn.run(app, host="SOURCE_IP", port=port)
    


