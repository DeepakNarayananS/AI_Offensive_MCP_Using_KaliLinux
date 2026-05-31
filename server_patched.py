#! /usr/bin/python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import traceback
import threading
from typing import Dict, Any
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

app = Flask(__name__)

class CommandExecutor:
    """Class to handle command execution with better timeout management"""

    def __init__(self, command, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        # Determine if we should use shell mode based on command type
        self.use_shell = isinstance(command, str)
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=self.use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command) -> Dict[str, Any]:
    """
    Execute a command and return the result.

    Args:
        command: The command to execute (list for safe mode, string for shell mode)

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


def get_string(params, key):
    value = params.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Invalid or missing field: {key}")
    return value.strip()


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.get_json()
        command = get_string(params, "command")
        return jsonify(execute_command(command))
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = ["nmap"] + shlex.split(scan_type)

        if ports:
            command += ["-p", ports]

        if additional_args:
            command += shlex.split(additional_args)

        command.append(target)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = ["gobuster", mode, "-u", url, "-w", wordlist]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = ["dirb", url, wordlist]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = ["nikto", "-h", target]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = ["sqlmap", "-u", url, "--batch"]

        if data:
            command += ["--data", data]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Validate module name (allow only alphanumeric, slashes, underscores, hyphens)
        if not re.match(r'^[a-zA-Z0-9/_-]+$', module):
            return jsonify({"error": "Invalid module name"}), 400

        # Create an MSF resource script with validated options
        resource_content = f"use {module}\n"
        for key, value in options.items():
            # Validate option keys
            if not re.match(r'^[a-zA-Z0-9_]+$', str(key)):
                return jsonify({"error": f"Invalid option key: {key}"}), 400
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file
        resource_file = "/tmp/mks_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        command = ["msfconsole", "-q", "-r", resource_file]
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = ["hydra", "-t", "4"]

        if username:
            command += ["-l", username]
        elif username_file:
            command += ["-L", username_file]

        if password:
            command += ["-p", password]
        elif password_file:
            command += ["-P", password_file]

        command += [target, service]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = ["john"]

        if format_type:
            command.append(f"--format={format_type}")

        if wordlist:
            command.append(f"--wordlist={wordlist}")

        if additional_args:
            command += shlex.split(additional_args)

        command.append(hash_file)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = ["wpscan", "--url", url]

        if additional_args:
            command += shlex.split(additional_args)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = ["enum4linux"] + shlex.split(additional_args) + [target]
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(["which", tool])
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
    })

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="IP address to bind the server to (default: 127.0.0.1 for localhost only)")
    return parser.parse_args()

# ===================== Metasploit RPC integration (injected) =====================
MSF_RPC_PASSWORD = os.environ.get("MSF_RPC_PASSWORD", "KaliMcp!2026")
MSF_RPC_HOST = os.environ.get("MSF_RPC_HOST", "127.0.0.1")
MSF_RPC_PORT = int(os.environ.get("MSF_RPC_PORT", "55553"))

_msf_client = None


def get_msf_client():
    """Lazily connect to msfrpcd and cache the client (reconnect on failure)."""
    global _msf_client
    from pymetasploit3.msfrpc import MsfRpcClient
    if _msf_client is not None:
        try:
            _ = _msf_client.core.version
            return _msf_client
        except Exception:
            _msf_client = None
    _msf_client = MsfRpcClient(MSF_RPC_PASSWORD, host=MSF_RPC_HOST, port=MSF_RPC_PORT, ssl=False)
    return _msf_client


def _read_console_until_idle(console, timeout=120):
    """Read from an MSF console until it stops being busy or timeout expires."""
    import time as _t
    out = ""
    deadline = _t.time() + timeout
    _t.sleep(1)
    while _t.time() < deadline:
        r = console.read()
        out += r.get("data", "")
        if not r.get("busy", False):
            _t.sleep(0.5)
            r2 = console.read()
            out += r2.get("data", "")
            if not r2.get("busy", False):
                break
        _t.sleep(0.5)
    return out


def _session_map(client):
    """Return {str_id: info} for current sessions."""
    raw = client.sessions.list
    return {str(k): v for k, v in raw.items()}


@app.route("/api/msf/status", methods=["GET"])
def msf_status():
    try:
        c = get_msf_client()
        return jsonify({"success": True, "version": c.core.version, "sessions": _session_map(c)})
    except Exception as e:
        logger.exception("msf status failed")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/msf/run", methods=["POST"])
def msf_run():
    """Run a module via a console; any session created persists in msfrpcd."""
    try:
        params = request.json or {}
        module = params.get("module", "")
        options = params.get("options", {}) or {}
        payload = params.get("payload", "") or ""
        payload_options = params.get("payload_options", {}) or {}
        timeout = int(params.get("timeout", 120))
        run_as_job = bool(params.get("run_as_job", False))

        if not module or not re.match(r'^[a-zA-Z0-9/_-]+$', module):
            return jsonify({"success": False, "error": "Invalid or missing module"}), 400
        if payload and not re.match(r'^[a-zA-Z0-9/_-]+$', payload):
            return jsonify({"success": False, "error": "Invalid payload"}), 400

        c = get_msf_client()
        console = c.consoles.console()
        try:
            console.write("use %s\n" % module)
            for k, v in options.items():
                if not re.match(r'^[a-zA-Z0-9_]+$', str(k)):
                    return jsonify({"success": False, "error": "Invalid option key: %s" % k}), 400
                console.write("set %s %s\n" % (k, v))
            if payload:
                console.write("set PAYLOAD %s\n" % payload)
                for k, v in payload_options.items():
                    if not re.match(r'^[a-zA-Z0-9_]+$', str(k)):
                        return jsonify({"success": False, "error": "Invalid payload option key: %s" % k}), 400
                    console.write("set %s %s\n" % (k, v))
            console.write("run -j\n" if run_as_job else "run\n")
            output = _read_console_until_idle(console, timeout)
        finally:
            try:
                console.destroy()
            except Exception:
                pass
        return jsonify({"success": True, "output": output, "sessions": _session_map(c)})
    except Exception as e:
        logger.exception("msf run failed")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/msf/sessions", methods=["GET"])
def msf_sessions():
    try:
        c = get_msf_client()
        return jsonify({"success": True, "sessions": _session_map(c)})
    except Exception as e:
        logger.exception("msf sessions failed")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/msf/session/interact", methods=["POST"])
def msf_session_interact():
    """Run a command in an existing session and return its output."""
    import time as _t
    try:
        params = request.json or {}
        sid = str(params.get("session_id", ""))
        command = params.get("command", "")
        timeout = int(params.get("timeout", 30))
        if not sid:
            return jsonify({"success": False, "error": "session_id required"}), 400
        c = get_msf_client()
        smap = _session_map(c)
        if sid not in smap:
            return jsonify({"success": False, "error": "No such session: %s" % sid}), 404
        stype = smap[sid].get("type", "")
        sess = c.sessions.session(sid)
        if stype == "meterpreter":
            sess.write(command)
        else:
            sess.write(command + "\n")
        _t.sleep(2)
        output = sess.read()
        deadline = _t.time() + timeout
        while _t.time() < deadline:
            more = sess.read()
            if not more:
                break
            output += more
            _t.sleep(0.5)
        return jsonify({"success": True, "session_id": sid, "type": stype, "output": output})
    except Exception as e:
        logger.exception("msf session interact failed")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/msf/session/kill", methods=["POST"])
def msf_session_kill():
    try:
        params = request.json or {}
        sid = str(params.get("session_id", ""))
        if not sid:
            return jsonify({"success": False, "error": "session_id required"}), 400
        c = get_msf_client()
        c.sessions.session(sid).stop()
        return jsonify({"success": True, "killed": sid, "sessions": _session_map(c)})
    except Exception as e:
        logger.exception("msf session kill failed")
        return jsonify({"success": False, "error": str(e)}), 500
# =================== End Metasploit RPC integration ===================


if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    logger.info(f"Starting Kali Linux Tools API Server on {args.ip}:{API_PORT}")
    app.run(host=args.ip, port=API_PORT, debug=DEBUG_MODE)
