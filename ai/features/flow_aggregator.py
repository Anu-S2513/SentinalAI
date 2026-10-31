from datetime import datetime
import statistics
import json
import os
import time


# =========================================================
# ACTIVE NETWORK FLOWS
# =========================================================

flows = {}


# =========================================================
# PROTOCOL NUMBER
# =========================================================

def get_protocol_number(protocol):

    protocol_map = {
        "TCP": 6,
        "UDP": 17,
        "ICMP": 1,
        "OTHER": 0
    }

    return protocol_map.get(protocol, 0)


# =========================================================
# FLOW KEY
# =========================================================

def get_flow_key(packet):

    endpoint1 = (
        packet["source_ip"],
        str(packet["source_port"])
    )

    endpoint2 = (
        packet["destination_ip"],
        str(packet["destination_port"])
    )

    endpoints = sorted([
        endpoint1,
        endpoint2
    ])

    return (
        endpoints[0],
        endpoints[1],
        packet["protocol"]
    )


# =========================================================
# CREATE FLOW
# =========================================================

def create_flow(packet):

    now = datetime.now()

    return {
        "start_time": now,
        "last_time": now,

        "initiator_ip":
            packet["source_ip"],

        "initiator_port":
            str(packet["source_port"]),

        "forward_packets": 0,
        "backward_packets": 0,

        "forward_bytes": 0,
        "backward_bytes": 0,

        "packet_sizes": [],

        "syn_count": 0,
        "ack_count": 0,
        "rst_count": 0,
        "fin_count": 0
    }


# =========================================================
# UPDATE FLOW
# =========================================================

def update_flow(flow, packet):

    now = datetime.now()

    flow["last_time"] = now

    packet_size = packet["packet_size"]

    # -----------------------------------------------------
    # Determine packet direction
    # -----------------------------------------------------

    if (
        packet["source_ip"] == flow["initiator_ip"]
        and
        str(packet["source_port"]) == flow["initiator_port"]
    ):

        flow["forward_packets"] += 1
        flow["forward_bytes"] += packet_size

    else:

        flow["backward_packets"] += 1
        flow["backward_bytes"] += packet_size

    # -----------------------------------------------------
    # Store packet size
    # -----------------------------------------------------

    flow["packet_sizes"].append(
        packet_size
    )

    # -----------------------------------------------------
    # TCP flags
    # -----------------------------------------------------

    flags = str(
        packet["tcp_flags"]
    )

    if "S" in flags:
        flow["syn_count"] += 1

    if "A" in flags:
        flow["ack_count"] += 1

    if "R" in flags:
        flow["rst_count"] += 1

    if "F" in flags:
        flow["fin_count"] += 1


# =========================================================
# PROCESS PACKET
# =========================================================

def process_packet(
    packet,
    minimum_packets=5,
    prediction_interval=10
):

    """
    Processes a packet and updates its
    corresponding network flow.

    The ML prediction starts after the flow
    reaches the minimum number of packets.
    """

    flow_key = get_flow_key(
        packet
    )

    # -----------------------------------------------------
    # Create flow if necessary
    # -----------------------------------------------------

    if flow_key not in flows:

        flows[flow_key] = create_flow(
            packet
        )

    flow = flows[flow_key]

    # -----------------------------------------------------
    # Update flow
    # -----------------------------------------------------

    update_flow(
        flow,
        packet
    )

    # -----------------------------------------------------
    # Total packets
    # -----------------------------------------------------

    total_packets = (
        flow["forward_packets"]
        +
        flow["backward_packets"]
    )

    # -----------------------------------------------------
    # Wait until enough packets exist
    # -----------------------------------------------------

    if total_packets < minimum_packets:

        return None

    # -----------------------------------------------------
    # First prediction
    # -----------------------------------------------------

    if total_packets == minimum_packets:

        return get_flow_features(
            flow,
            packet
        )

    # -----------------------------------------------------
    # Periodic predictions
    # -----------------------------------------------------

    if (
        total_packets
        -
        minimum_packets
    ) % prediction_interval == 0:

        return get_flow_features(
            flow,
            packet
        )

    return None


# =========================================================
# GET ML FEATURES
# =========================================================

def get_flow_features(flow, packet):

    """
    Converts the aggregated network flow
    into the 14 features required by
    the Random Forest model.
    """

    # -----------------------------------------------------
    # Flow duration in microseconds
    # -----------------------------------------------------

    duration = (
        flow["last_time"]
        -
        flow["start_time"]
    ).total_seconds() * 1_000_000

    if duration <= 0:

        duration = 1

    # -----------------------------------------------------
    # Convert to seconds
    # -----------------------------------------------------

    duration_seconds = (
        duration / 1_000_000
    )

    # -----------------------------------------------------
    # Total packets
    # -----------------------------------------------------

    total_packets = (
        flow["forward_packets"]
        +
        flow["backward_packets"]
    )

    # -----------------------------------------------------
    # Total bytes
    # -----------------------------------------------------

    total_bytes = (
        flow["forward_bytes"]
        +
        flow["backward_bytes"]
    )

    # -----------------------------------------------------
    # Packet statistics
    # -----------------------------------------------------

    packet_sizes = (
        flow["packet_sizes"]
    )

    packet_mean = statistics.mean(
        packet_sizes
    )

    if len(packet_sizes) > 1:

        packet_std = statistics.pstdev(
            packet_sizes
        )

    else:

        packet_std = 0

    # -----------------------------------------------------
    # Flow rates
    # -----------------------------------------------------

    flow_bytes_per_second = (
        total_bytes
        /
        duration_seconds
    )

    flow_packets_per_second = (
        total_packets
        /
        duration_seconds
    )

    # -----------------------------------------------------
    # Return the 14 model features
    # -----------------------------------------------------

    return {

        "Protocol":
            get_protocol_number(
                packet["protocol"]
            ),

        "Flow Duration":
            duration,

        "Total Fwd Packets":
            flow["forward_packets"],

        "Total Backward Packets":
            flow["backward_packets"],

        "Fwd Packets Length Total":
            flow["forward_bytes"],

        "Bwd Packets Length Total":
            flow["backward_bytes"],

        "Flow Bytes/s":
            flow_bytes_per_second,

        "Flow Packets/s":
            flow_packets_per_second,

        "Packet Length Mean":
            packet_mean,

        "Packet Length Std":
            packet_std,

        "SYN Flag Count":
            flow["syn_count"],

        "ACK Flag Count":
            flow["ack_count"],

        "RST Flag Count":
            flow["rst_count"],

        "FIN Flag Count":
            flow["fin_count"]
    }


# =========================================================
# GET TRANSFER DIRECTION
# =========================================================

def get_transfer_direction(
    forward_bytes,
    backward_bytes
):

    """
    Determines the dominant data-transfer direction
    of a network flow.

    If one direction has at least 3x more data,
    classify it as UPLOAD or DOWNLOAD.

    Otherwise classify it as BIDIRECTIONAL.
    """

    # No data transferred yet
    if forward_bytes == 0 and backward_bytes == 0:
        return "NO DATA"

    # Only backward traffic
    if forward_bytes == 0:
        return "DOWNLOAD"

    # Only forward traffic
    if backward_bytes == 0:
        return "UPLOAD"

    # Download:
    # destination/server sends much more data
    if backward_bytes >= forward_bytes * 3:
        return "DOWNLOAD"

    # Upload:
    # source/client sends much more data
    if forward_bytes >= backward_bytes * 3:
        return "UPLOAD"

    # Similar amount in both directions
    return "BIDIRECTIONAL"


# =========================================================
# GET ACTIVE FLOWS
# =========================================================

def get_active_flows():

    """
    Returns aggregated network flows
    for behavioral analysis.

    One entry represents one network flow,
    not one individual packet.
    """

    results = []

    for flow_key, flow in flows.items():

        # -------------------------------------------------
        # Total packets
        # -------------------------------------------------

        total_packets = (
            flow["forward_packets"]
            +
            flow["backward_packets"]
        )

        # -------------------------------------------------
        # Total bytes
        # -------------------------------------------------

        total_bytes = (
            flow["forward_bytes"]
            +
            flow["backward_bytes"]
        )

        # -------------------------------------------------
        # Transfer direction
        # -------------------------------------------------

        transfer_direction = get_transfer_direction(
            flow["forward_bytes"],
            flow["backward_bytes"]
        )

        # -------------------------------------------------
        # Duration
        # -------------------------------------------------

        duration = (
            flow["last_time"]
            -
            flow["start_time"]
        ).total_seconds()

        # -------------------------------------------------
        # Flow endpoints
        # -------------------------------------------------

        endpoint1 = flow_key[0]
        endpoint2 = flow_key[1]

        initiator = (
            flow["initiator_ip"],
            flow["initiator_port"]
        )

        if endpoint1 == initiator:

            destination = endpoint2

        else:

            destination = endpoint1

        # -------------------------------------------------
        # Behavioral flow record
        # -------------------------------------------------

        results.append({

            "source_ip":
                flow["initiator_ip"],

            "destination_ip":
                destination[0],

            "source_port":
                flow["initiator_port"],

            "destination_port":
                destination[1],

            "protocol":
                flow_key[2],

            "total_packets":
                total_packets,

            "forward_packets":
                flow["forward_packets"],

            "backward_packets":
                flow["backward_packets"],

            "forward_bytes":
                flow["forward_bytes"],

            "backward_bytes":
                flow["backward_bytes"],

            "total_bytes":
                total_bytes,

            "transfer_direction":
                transfer_direction,

            "duration":
                round(
                    duration,
                    2
                ),

            "syn_count":
                flow["syn_count"],

            "ack_count":
                flow["ack_count"],

            "rst_count":
                flow["rst_count"],

            "fin_count":
                flow["fin_count"]
        })

    return results


# =========================================================
# SAVE ACTIVE FLOWS
# =========================================================

def save_active_flows(file_path):

    """
    Saves current aggregated flows to a JSON file.

    FastAPI reads this file to display
    behavioral network activity.

    Updates the existing snapshot in place and preserves the session marker.
    """

    active_flows = get_active_flows()
    session_started_at = None

    if os.path.isfile(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as existing_file:
                previous_snapshot = json.load(existing_file)
            if isinstance(previous_snapshot, dict):
                session_started_at = previous_snapshot.get(
                    "session_started_at"
                )
        except (OSError, json.JSONDecodeError):
            pass

    # -----------------------------------------------------
    # Create directory
    # -----------------------------------------------------

    directory = os.path.dirname(
        file_path
    )

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )

    snapshot = {
        "total_flows": len(active_flows),
        "flows": active_flows
    }
    if session_started_at:
        snapshot["session_started_at"] = session_started_at

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(snapshot, file, indent=2)
