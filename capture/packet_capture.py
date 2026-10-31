import sys
import os
import time
import threading

from scapy.all import sniff


# ============================================================
# PROJECT PATH
# ============================================================

project_root = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.append(project_root)


# ============================================================
# SENTINELAI MODULES
# ============================================================

from capture.parser import parse_packet

from ai.realtime_detector import analyze_packet

from ai.features.flow_aggregator import (
    save_active_flows
)
from ai.logs.session_state import start_new_session, update_capture_status


# ============================================================
# ACTIVE FLOWS FILE
# ============================================================

ACTIVE_FLOWS_FILE = os.path.join(
    project_root,
    "ai",
    "logs",
    "active_flows.json"
)


# ============================================================
# STATISTICS
# ============================================================

captured_count = 0

prediction_count = 0

normal_count = 0

attack_count = 0

latest_probability = 0.0

latest_action = "WAITING"

last_display_time = time.time()
capture_heartbeat_stop = threading.Event()


def capture_heartbeat_loop():
    while not capture_heartbeat_stop.wait(5):
        try:
            update_capture_status("RUNNING")
        except OSError as error:
            print(f"[WARNING] Could not update capture health: {error}")


# ============================================================
# SAVE CURRENT BEHAVIORAL FLOWS
# ============================================================

def save_current_flows():

    try:

        save_active_flows(
            ACTIVE_FLOWS_FILE
        )

    except Exception as error:

        print(
            f"\n[WARNING] "
            f"Could not save active flows: {error}"
        )


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    global captured_count
    global prediction_count
    global normal_count
    global attack_count
    global latest_probability
    global latest_action
    global last_display_time


    # --------------------------------------------------------
    # PARSE PACKET
    # --------------------------------------------------------

    parsed_packet = parse_packet(
        packet
    )


    # Ignore packets that do not contain
    # a supported IP layer
    if parsed_packet is None:

        return


    captured_count += 1


    # --------------------------------------------------------
    # SENTINELAI ANALYSIS
    # --------------------------------------------------------

    try:

        result = analyze_packet(
            parsed_packet
        )


        # ----------------------------------------------------
        # IMPORTANT
        #
        # analyze_packet() has already updated
        # the flow aggregator at this point.
        #
        # Therefore save the flows AFTER analysis.
        # ----------------------------------------------------

        save_current_flows()


        # ----------------------------------------------------
        # Flow does not have enough packets yet
        # ----------------------------------------------------

        if result is None:

            return


        prediction_count += 1


        prediction = result[
            "prediction"
        ]


        probability = result[
            "attack_probability"
        ]


        firewall_action = result[
            "firewall_action"
        ]


        latest_probability = (
            probability
        )


        latest_action = (
            firewall_action
        )


        # ----------------------------------------------------
        # ATTACK DETECTED
        # ----------------------------------------------------

        if prediction == "ATTACK":

            attack_count += 1


            print()

            print(
                "!" * 60
            )

            print(
                "              🚨 ATTACK DETECTED 🚨"
            )

            print(
                "!" * 60
            )


            print(
                f"Source      : "
                f"{parsed_packet['source_ip']}:"
                f"{parsed_packet['source_port']}"
            )


            print(
                f"Destination : "
                f"{parsed_packet['destination_ip']}:"
                f"{parsed_packet['destination_port']}"
            )


            print(
                f"Protocol    : "
                f"{parsed_packet['protocol']}"
            )


            print(
                f"Probability : "
                f"{probability:.2f}"
            )


            print(
                f"Prediction  : "
                f"{prediction}"
            )


            print(
                f"Firewall    : "
                f"{firewall_action}"
            )


            print(
                f"Enforcement : "
                f"{result.get('enforcement_status', 'N/A')}"
            )


            print(
                "!" * 60
            )

            print()


        else:

            normal_count += 1


        # ----------------------------------------------------
        # PERIODIC STATUS
        # ----------------------------------------------------

        current_time = time.time()


        if (
            current_time
            -
            last_display_time
            >= 5
        ):

            print()

            print(
                "-" * 60
            )

            print(
                "SENTINELAI STATUS"
            )

            print(
                "-" * 60
            )


            print(
                f"Packets Captured : "
                f"{captured_count}"
            )


            print(
                f"Predictions      : "
                f"{prediction_count}"
            )


            print(
                f"Normal           : "
                f"{normal_count}"
            )


            print(
                f"Attacks          : "
                f"{attack_count}"
            )


            print(
                f"Latest Risk      : "
                f"{latest_probability:.2f}"
            )


            print(
                f"Latest Action    : "
                f"{latest_action}"
            )


            print(
                f"Flow Data        : "
                f"{ACTIVE_FLOWS_FILE}"
            )


            print(
                "-" * 60
            )


            last_display_time = (
                current_time
            )


    except Exception as error:

        print(
            f"\n[ERROR] "
            f"ML analysis failed: {error}"
        )


        # Even if ML analysis fails,
        # try to save the current flow state.
        save_current_flows()


# ============================================================
# START SENTINELAI
# ============================================================

print(
    "=" * 60
)

print(
    "       SENTINELAI - REAL TIME NETWORK MONITOR"
)

print(
    "=" * 60
)

print()

print(
    "Status : RUNNING"
)

print()

print(
    "Monitoring network traffic..."
)

print(
    "Behavioral flow aggregation : ENABLED"
)

print(
    "Flow storage :"
)

print(
    ACTIVE_FLOWS_FILE
)

print()

print(
    "Status updates appear every 5 seconds."
)

print(
    "Press CTRL+C to stop."
)

print()


# ============================================================
# START PACKET CAPTURE
# ============================================================

try:

    # Keep prior CSV history for reference, but start a fresh dashboard
    # session and replace any stale active-flow snapshot.
    session_started_at = start_new_session()
    update_capture_status("RUNNING")
    save_current_flows()
    print(f"Dashboard session started: {session_started_at}")

    heartbeat_thread = threading.Thread(
        target=capture_heartbeat_loop,
        name="SentinelAI-Capture-Heartbeat",
        daemon=True
    )
    heartbeat_thread.start()

    sniff(
        prn=packet_callback,
        store=False
    )


except KeyboardInterrupt:

    print()

    print()

    print(
        "=" * 60
    )

    print(
        "           SENTINELAI - STOPPED"
    )

    print(
        "=" * 60
    )


finally:

    capture_heartbeat_stop.set()
    heartbeat_thread = locals().get("heartbeat_thread")
    if heartbeat_thread is not None:
        heartbeat_thread.join(timeout=2)
    try:
        update_capture_status("STOPPED")
    except OSError as error:
        print(f"[WARNING] Could not mark capture stopped: {error}")

    # --------------------------------------------------------
    # Final flow save
    # --------------------------------------------------------

    save_current_flows()


    print()

    print(
        "FINAL STATISTICS"
    )

    print(
        "-" * 60
    )


    print(
        f"Packets Captured : "
        f"{captured_count}"
    )


    print(
        f"Predictions      : "
        f"{prediction_count}"
    )


    print(
        f"Normal           : "
        f"{normal_count}"
    )


    print(
        f"Attacks          : "
        f"{attack_count}"
    )


    print(
        f"Latest Risk      : "
        f"{latest_probability:.2f}"
    )


    print(
        f"Latest Action    : "
        f"{latest_action}"
    )


    print(
        f"Behavioral Flows : "
        f"{ACTIVE_FLOWS_FILE}"
    )


    print(
        "-" * 60
    )

    print(
        "SentinelAI monitoring stopped."
    )

    print(
        "=" * 60
    )
