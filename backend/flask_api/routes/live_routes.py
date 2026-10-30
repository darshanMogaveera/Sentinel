from flask import Blueprint, request, jsonify
from scapy.all import get_if_list, conf

from backend.services.packet_capture_service import packet_capture_service
from backend.services.logging_service import logger_service

live_bp = Blueprint('live_bp', __name__, url_prefix='/api/live')


def _normalize_nfstream_source(pcap_name: str) -> str:
    """
    Scapy's get_if_list() on Windows returns Python strings where each
    backslash is escaped, e.g. '\\\\Device\\\\NPF_Loopback' which when
    printed shows as '\\\\Device\\\\NPF_Loopback'.

    NFStream's is_interface() calls capture_get_interface() via CFFI and
    expects a *single*-backslash path: '\\Device\\NPF_Loopback'.

    Strategy: if the string starts with '\\\\Device' (double-backslash in
    the actual string bytes), collapse every '\\\\' pair to a single '\\'.
    """
    # The Scapy string in memory: first two chars are backslash+backslash
    if pcap_name.startswith('\\\\'):
        return pcap_name.replace('\\\\', '\\')
    return pcap_name


@live_bp.route('/interfaces', methods=['GET'])
def get_interfaces():
    """
    Return network interfaces with a human-friendly display name
    and the correct NFStream-compatible source identifier.
    'name'           – the raw Scapy pcap device path (may be double-backslash)
    'nfstream_source'– the normalised single-backslash path accepted by NFStream
    'label'          – friendly display name shown in the UI
    'description'    – additional adapter description
    """
    try:
        interfaces = []

        for pcap_name in get_if_list():
            friendly_name = pcap_name
            description = ""
            nfstream_source = _normalize_nfstream_source(pcap_name)

            try:
                iface = conf.ifaces.get(pcap_name)

                if iface:
                    friendly_name = (
                        getattr(iface, "name", None)
                        or getattr(iface, "description", None)
                        or pcap_name
                    )
                    description = (
                        getattr(iface, "description", None)
                        or ""
                    )

            except Exception:
                pass

            # Verify that NFStream actually accepts this source
            try:
                from nfstream.streamer import is_interface
                validated = is_interface(nfstream_source)
                nfstream_valid = validated is not None
                if validated is not None:
                    nfstream_source = validated
            except Exception:
                nfstream_valid = True  # assume valid if we can't check

            interfaces.append({
                "name": nfstream_source,   # use normalised form as the primary key
                "raw_name": pcap_name,
                "label": friendly_name,
                "description": description,
                "nfstream_valid": nfstream_valid
            })

        return jsonify({"interfaces": interfaces}), 200

    except Exception as e:
        logger_service.log_error(
            e,
            {"context": "Get network interfaces"}
        )

        return jsonify({
            "error": str(e)
        }), 500


@live_bp.route('/status', methods=['GET'])
def get_live_status():
    from backend.services.database_service import db_service

    run_id = getattr(
        packet_capture_service,
        'current_run_id',
        None
    )

    devices = []

    if run_id:
        devices = db_service.get_observed_devices(
            run_id=run_id
        )

    stats = packet_capture_service.stats
    last_error = stats.get("last_error") if stats else None
    if not last_error and getattr(packet_capture_service, "_startup_error", None):
        last_error = packet_capture_service._startup_error

    status = {
        "running": packet_capture_service.is_running,
        "interface": packet_capture_service.current_interface,
        "run_id": run_id,
        "stats": stats,
        "observed_devices": devices,
        "error": last_error
    }

    return jsonify(status), 200


@live_bp.route('/run_stats/<run_id>', methods=['GET'])
def get_run_stats(run_id: str):
    """Fetch stats for a specific simulation run_id directly."""
    stats = packet_capture_service.get_run_stats(run_id)
    return jsonify({"run_id": run_id, "stats": stats}), 200


@live_bp.route('/devices', methods=['GET'])
def get_live_devices():
    from backend.services.database_service import db_service

    try:
        run_id = getattr(
            packet_capture_service,
            'current_run_id',
            None
        )

        if run_id:
            devices = db_service.get_observed_devices(
                run_id=run_id
            )
        else:
            devices = []

        return jsonify({
            "devices": devices
        }), 200

    except Exception as e:
        logger_service.log_error(
            e,
            {"context": "Get observed devices"}
        )

        return jsonify({
            "error": str(e)
        }), 500


@live_bp.route('/start', methods=['POST'])
def start_live_capture():
    data = request.get_json() or {}
    interface = data.get("interface")

    if not interface:
        return jsonify({
            "error": "Interface is required to start live capture."
        }), 400

    if packet_capture_service.is_running:
        return jsonify({
            "error": "Capture is already running."
        }), 400

    try:
        from flask import current_app

        app = current_app._get_current_object()

        packet_capture_service.start(
            interface,
            app=app
        )

        return jsonify({
            "message": (
                f"Packet capture started on interface "
                f"'{packet_capture_service.current_interface}'."
            )
        }), 200

    except Exception as e:
        logger_service.log_error(
            e,
            {"context": "Start live capture"}
        )

        return jsonify({
            "error": str(e)
        }), 500


@live_bp.route('/stop', methods=['POST'])
def stop_live_capture():
    if not packet_capture_service.is_running:
        return jsonify({
            "message": "Capture is not running."
        }), 200

    try:
        packet_capture_service.stop()

        return jsonify({
            "message": "Packet capture stopped."
        }), 200

    except Exception as e:
        logger_service.log_error(
            e,
            {"context": "Stop live capture"}
        )

        return jsonify({
            "error": str(e)
        }), 500


import threading
import socket
import time


def validate_simulation_config(config):
    """
    Validates simulation configuration.
    Rules:
    1. Allowed destination IP: strictly '127.0.0.1'.
    2. Valid port ranges: 1 <= port <= 65535, start <= end.
    3. Maximum number of destination ports: 11 (minimum: 1).
    Returns: (is_valid: bool, error_message: str, validated_config: dict)
    """
    if not isinstance(config, dict):
        return False, "Config must be a JSON object.", None

    dest_ip = config.get("dest_ip", "127.0.0.1")
    if dest_ip != "127.0.0.1":
        return False, f"Invalid dest_ip '{dest_ip}': only '127.0.0.1' is allowed.", None

    dest_ports = None

    # 1. Check explicit list of ports
    if "dest_ports" in config:
        raw_ports = config.get("dest_ports")
        if not isinstance(raw_ports, list) or len(raw_ports) == 0:
            return False, "dest_ports must be a non-empty list of integers.", None
        ports = []
        for p in raw_ports:
            try:
                p_int = int(p)
            except (ValueError, TypeError):
                return False, f"Invalid port value: {p}", None
            if p_int < 1 or p_int > 65535:
                return False, f"Port {p_int} is out of valid range (1-65535).", None
            ports.append(p_int)
        dest_ports = ports

    # 2. Check port_range formatted as string "12340-12349" or list [12340, 12349]
    elif "port_range" in config:
        pr = config.get("port_range")
        if isinstance(pr, str) and "-" in pr:
            parts = pr.split("-")
            try:
                s, e = int(parts[0].strip()), int(parts[1].strip())
            except (ValueError, TypeError):
                return False, f"Invalid port_range format: {pr}", None
        elif isinstance(pr, (list, tuple)) and len(pr) == 2:
            try:
                s, e = int(pr[0]), int(pr[1])
            except (ValueError, TypeError):
                return False, f"Invalid port_range format: {pr}", None
        else:
            return False, "port_range must be a 'start-end' string or [start, end] list.", None

        if s < 1 or s > 65535 or e < 1 or e > 65535:
            return False, "Port values must be between 1 and 65535.", None
        if s > e:
            return False, f"Start port ({s}) cannot be greater than end port ({e}).", None
        dest_ports = list(range(s, e + 1))

    # 3. Check start_port/end_port or port_range_start/port_range_end
    elif any(k in config for k in ("port_range_start", "port_range_end", "start_port", "end_port")):
        s_val = config.get("port_range_start") if "port_range_start" in config else config.get("start_port", 12340)
        e_val = config.get("port_range_end") if "port_range_end" in config else config.get("end_port", 12349)
        try:
            s = int(s_val)
            e = int(e_val)
        except (ValueError, TypeError):
            return False, "Port range values must be integers.", None
        if s < 1 or s > 65535 or e < 1 or e > 65535:
            return False, "Port values must be between 1 and 65535.", None
        if s > e:
            return False, f"Start port ({s}) cannot be greater than end port ({e}).", None
        dest_ports = list(range(s, e + 1))

    # 4. Check multi_port boolean flag
    elif config.get("multi_port") is True:
        dest_ports = list(range(12340, 12350))

    # 5. Check single dest_port
    elif "dest_port" in config:
        dp = config.get("dest_port")
        try:
            dp_int = int(dp)
        except (ValueError, TypeError):
            return False, f"Invalid dest_port value: {dp}", None
        if dp_int < 1 or dp_int > 65535:
            return False, f"Port {dp_int} is out of valid range (1-65535).", None
        dest_ports = [dp_int]

    # 6. Default fallback: default range 12340-12349 (10 ports)
    else:
        dest_ports = list(range(12340, 12350))

    if len(dest_ports) > 11:
        return False, f"Port range exceeds maximum allowed limit of 11 ports (got {len(dest_ports)}).", None

    if len(dest_ports) < 1:
        return False, "At least one destination port must be specified.", None

    validated = dict(config)
    validated["dest_ip"] = dest_ip
    validated["dest_ports"] = dest_ports
    validated["dest_port"] = dest_ports[0]
    return True, "", validated


def run_simulation_thread(config, run_id):
    start_time = time.time()
    packets_sent = 0
    send_errors = []

    protocol = config.get(
        "protocol",
        "UDP"
    ).upper()

    dest_ip = config.get(
        "dest_ip",
        "127.0.0.1"
    )

    dest_ports = config.get("dest_ports")
    if not dest_ports:
        dest_ports = [int(config.get("dest_port", 12345))]

    num_connections = int(
        config.get(
            "num_connections",
            1
        )
    )

    packets_per_connection = int(
        config.get(
            "packets_per_connection",
            5
        )
    )

    total_packets = len(dest_ports) * num_connections * packets_per_connection

    payload_size = int(
        config.get(
            "payload_size",
            64
        )
    )

    delay_packets = float(
        config.get(
            "delay_between_packets",
            0.02
        )
    )
    if delay_packets <= 0:
        delay_packets = 0.001

    delay_connections = float(
        config.get(
            "delay_between_connections",
            0.05
        )
    )

    payload = b"X" * payload_size

    logger_service.logger.info(
        f"[STAGE 3][{run_id}] Simulator started: sending {total_packets} datagrams ({len(dest_ports)} ports x {num_connections} conn x {packets_per_connection} pkts) via {protocol} to {dest_ip}:{dest_ports}"
    )

    time.sleep(0.2)

    try:
        if protocol == "TCP":
            from scapy.all import IP, TCP, send
            for target_port in dest_ports:
                for _ in range(num_connections):
                    try:
                        pkt = IP(dst=dest_ip)/TCP(sport=55100, dport=target_port, flags="S")
                        send(pkt, verbose=False)
                        packets_sent += 1
                    except Exception as send_err:
                        send_errors.append(str(send_err))

                    if delay_connections > 0:
                        time.sleep(delay_connections)
        else:
            for target_port in dest_ports:
                for _ in range(num_connections):
                    sock = socket.socket(
                        socket.AF_INET,
                        socket.SOCK_DGRAM
                    )

                    for _ in range(packets_per_connection):
                        try:
                            sock.sendto(
                                payload,
                                (dest_ip, target_port)
                            )
                            packets_sent += 1
                        except Exception as send_err:
                            send_errors.append(str(send_err))

                        if delay_packets > 0:
                            time.sleep(delay_packets)

                    sock.close()

                    if delay_connections > 0:
                        time.sleep(delay_connections)

    except Exception as e:
        logger_service.logger.error(
            f"[STAGE 3][{run_id}] Simulation thread exception: {e}"
        )
        send_errors.append(str(e))

    duration = time.time() - start_time

    logger_service.logger.info(
        f"[STAGE 3][{run_id}] Simulator finished: sent {packets_sent}/{total_packets} datagrams to {dest_ip}:{dest_ports} in {duration:.2f}s (send_errors: {len(send_errors)})"
    )

    from backend.services.packet_capture_service import (
        packet_capture_service
    )

    packet_capture_service.mark_traffic_finished(
        run_id
    )

    # Allow flow idle timeout (1.0s) to elapse, then trigger clock tick to flush flow immediately
    time.sleep(1.2)
    try:
        for _ in range(3):
            tick_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tick_sock.sendto(b"tick", ("127.0.0.1", 54321))
            tick_sock.close()
            time.sleep(0.3)
    except Exception:
        pass


@live_bp.route('/simulate', methods=['POST'])
def run_simulation():
    raw_config = request.get_json() or {}

    is_valid, error_msg, validated_config = validate_simulation_config(raw_config)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    if not packet_capture_service.is_running:
        return jsonify({
            "error": (
                "Capture is not running. "
                "Start live capture before "
                "running a traffic simulation."
            )
        }), 400

    run_id = f"SIM-{int(time.time())}"

    dest_ip = validated_config["dest_ip"]
    dest_ports = validated_config["dest_ports"]
    dest_port = validated_config["dest_port"]

    packet_capture_service.reset_run(
        run_id,
        dest_ip=dest_ip,
        dest_port=dest_port,
        dest_ports=dest_ports
    )

    thread = threading.Thread(
        target=run_simulation_thread,
        args=(
            validated_config,
            run_id
        ),
        daemon=True
    )

    thread.start()

    return jsonify({
        "message": "Simulation started.",
        "run_id": run_id,
        "config": validated_config
    }), 200