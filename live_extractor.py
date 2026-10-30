import math

SENTINEL_PORTS = {5000, 5173}  # Sentinel's own API/dev ports — always filtered out

FEATURE_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags', 
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 
    'Idle Max', 'Idle Min'
]

def safe(val):
    try:
        if val is None:
            return 0
        if isinstance(val, bool):
            return int(val)
        if isinstance(val, int):
            return val
        if isinstance(val, float):
            if math.isfinite(val):
                return float(val)
            return 0
        return float(val)
    except Exception:
        return 0

class LiveFlowExtractor:
    def __init__(self, idle_timeout=5.0):
        self.idle_timeout = idle_timeout
        self.expired_flows = []
        self.sim_target_ip = None
        self.sim_target_port = None
        self.flows = {} # Dummy dict for API compatibility if needed

    def set_simulation_target(self, dest_ip: str, dest_port: int = None, dest_ports: list = None):
        self.sim_target_ip = dest_ip
        if dest_ports:
            self.sim_target_ports = set(int(p) for p in dest_ports)
            self.sim_target_port = list(dest_ports)[0]
        elif dest_port is not None:
            self.sim_target_port = int(dest_port)
            self.sim_target_ports = {int(dest_port)}
        else:
            self.sim_target_port = None
            self.sim_target_ports = None

    def extract_features_from_nfstream(self, flow):
        src_port = safe(getattr(flow, "src_port", None))
        dst_port = safe(getattr(flow, "dst_port", None))

        # Apply Sentinel filter
        if src_port in SENTINEL_PORTS or dst_port in SENTINEL_PORTS:
            return None

        # Apply simulation filter
        target_ports = getattr(self, "sim_target_ports", None)
        if target_ports is not None:
            involves_target_port = (
                src_port in target_ports or
                dst_port in target_ports
            )
            src_ip = str(getattr(flow, "src_ip", "") or "")
            dst_ip = str(getattr(flow, "dst_ip", "") or "")

            loopback_hosts = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::ffff:127.0.0.1"}
            if self.sim_target_ip in loopback_hosts:
                involves_target_ip = (src_ip in loopback_hosts or dst_ip in loopback_hosts)
            else:
                involves_target_ip = (
                    self.sim_target_ip is None or
                    src_ip == self.sim_target_ip or
                    dst_ip == self.sim_target_ip
                )

            if not (involves_target_port and involves_target_ip):
                return None
        elif self.sim_target_port is not None:
            involves_target_port = (
                src_port == self.sim_target_port or
                dst_port == self.sim_target_port
            )
            src_ip = str(getattr(flow, "src_ip", "") or "")
            dst_ip = str(getattr(flow, "dst_ip", "") or "")

            loopback_hosts = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::ffff:127.0.0.1"}
            if self.sim_target_ip in loopback_hosts:
                involves_target_ip = (src_ip in loopback_hosts or dst_ip in loopback_hosts)
            else:
                involves_target_ip = (
                    self.sim_target_ip is None or
                    src_ip == self.sim_target_ip or
                    dst_ip == self.sim_target_ip
                )

            if not (involves_target_port and involves_target_ip):
                return None

        f = {}
        dur_ms = safe(getattr(flow, "bidirectional_duration_ms", 0))
        dur_s = dur_ms / 1000 if dur_ms > 0 else 0

        f["Destination Port"] = flow.dst_port
        f["Flow Duration"] = dur_ms * 1000  # Convert to microseconds for CIC-IDS2017 standard
        
        f["Total Fwd Packets"] = safe(getattr(flow, "src2dst_packets", 0))
        f["Total Backward Packets"] = safe(getattr(flow, "dst2src_packets", 0))
        f["Total Length of Fwd Packets"] = safe(getattr(flow, "src2dst_bytes", 0))
        f["Total Length of Bwd Packets"] = safe(getattr(flow, "dst2src_bytes", 0))

        f["Fwd Packet Length Max"] = safe(getattr(flow, "src2dst_max_ps", 0))
        f["Fwd Packet Length Min"] = safe(getattr(flow, "src2dst_min_ps", 0))
        f["Fwd Packet Length Mean"] = safe(getattr(flow, "src2dst_mean_ps", 0))
        f["Fwd Packet Length Std"] = safe(getattr(flow, "src2dst_stddev_ps", 0))
        f["Bwd Packet Length Max"] = safe(getattr(flow, "dst2src_max_ps", 0))
        f["Bwd Packet Length Min"] = safe(getattr(flow, "dst2src_min_ps", 0))
        f["Bwd Packet Length Mean"] = safe(getattr(flow, "dst2src_mean_ps", 0))
        f["Bwd Packet Length Std"] = safe(getattr(flow, "dst2src_stddev_ps", 0))

        total_bytes = safe(getattr(flow, "bidirectional_bytes", 0))
        total_pkts = safe(getattr(flow, "bidirectional_packets", 0))
        f["Flow Bytes/s"] = safe(total_bytes / dur_s) if dur_s > 0 else 0
        f["Flow Packets/s"] = safe(total_pkts / dur_s) if dur_s > 0 else 0

        # IATs (convert to microseconds)
        f["Flow IAT Mean"] = safe(getattr(flow, "bidirectional_mean_piat_ms", 0)) * 1000
        f["Flow IAT Std"] = safe(getattr(flow, "bidirectional_stddev_piat_ms", 0)) * 1000
        f["Flow IAT Max"] = safe(getattr(flow, "bidirectional_max_piat_ms", 0)) * 1000
        f["Flow IAT Min"] = safe(getattr(flow, "bidirectional_min_piat_ms", 0)) * 1000

        f["Fwd IAT Total"] = safe(getattr(flow, "src2dst_duration_ms", 0)) * 1000
        f["Fwd IAT Mean"] = safe(getattr(flow, "src2dst_mean_piat_ms", 0)) * 1000
        f["Fwd IAT Std"] = safe(getattr(flow, "src2dst_stddev_piat_ms", 0)) * 1000
        f["Fwd IAT Max"] = safe(getattr(flow, "src2dst_max_piat_ms", 0)) * 1000
        f["Fwd IAT Min"] = safe(getattr(flow, "src2dst_min_piat_ms", 0)) * 1000
        f["Bwd IAT Total"] = safe(getattr(flow, "dst2src_duration_ms", 0)) * 1000
        f["Bwd IAT Mean"] = safe(getattr(flow, "dst2src_mean_piat_ms", 0)) * 1000
        f["Bwd IAT Std"] = safe(getattr(flow, "dst2src_stddev_piat_ms", 0)) * 1000
        f["Bwd IAT Max"] = safe(getattr(flow, "dst2src_max_piat_ms", 0)) * 1000
        f["Bwd IAT Min"] = safe(getattr(flow, "dst2src_min_piat_ms", 0)) * 1000

        f["Fwd PSH Flags"] = safe(getattr(flow, "src2dst_psh_packets", 0))
        f["Fwd URG Flags"] = safe(getattr(flow, "src2dst_urg_packets", 0))
        
        f["Fwd Header Length"] = 40 if f["Total Fwd Packets"] > 0 else 0
        f["Bwd Header Length"] = 40 if f["Total Backward Packets"] > 0 else 0
        f["Fwd Packets/s"] = safe(f["Total Fwd Packets"] / dur_s) if dur_s > 0 else 0
        f["Bwd Packets/s"] = safe(f["Total Backward Packets"] / dur_s) if dur_s > 0 else 0

        f["Min Packet Length"] = safe(getattr(flow, "bidirectional_min_ps", 0))
        f["Max Packet Length"] = safe(getattr(flow, "bidirectional_max_ps", 0))
        f["Packet Length Mean"] = safe(getattr(flow, "bidirectional_mean_ps", 0))
        f["Packet Length Std"] = safe(getattr(flow, "bidirectional_stddev_ps", 0))
        f["Packet Length Variance"] = safe((getattr(flow, "bidirectional_stddev_ps", 0)) ** 2)

        f["FIN Flag Count"] = safe(getattr(flow, "bidirectional_fin_packets", 0))
        f["SYN Flag Count"] = safe(getattr(flow, "bidirectional_syn_packets", 0))
        f["RST Flag Count"] = safe(getattr(flow, "bidirectional_rst_packets", 0))
        f["PSH Flag Count"] = safe(getattr(flow, "bidirectional_psh_packets", 0))
        f["ACK Flag Count"] = safe(getattr(flow, "bidirectional_ack_packets", 0))
        f["URG Flag Count"] = safe(getattr(flow, "bidirectional_urg_packets", 0))
        f["CWE Flag Count"] = safe(getattr(flow, "bidirectional_cwr_packets", 0))
        f["ECE Flag Count"] = safe(getattr(flow, "bidirectional_ece_packets", 0))

        src_bytes = safe(getattr(flow, "src2dst_bytes", 0))
        dst_bytes = safe(getattr(flow, "dst2src_bytes", 0))
        f["Down/Up Ratio"] = safe((dst_bytes / src_bytes) if src_bytes > 0 else 0)
        f["Average Packet Size"] = safe((total_bytes / total_pkts) if total_pkts > 0 else 0)
        f["Avg Fwd Segment Size"] = safe(getattr(flow, "src2dst_mean_ps", 0))
        f["Avg Bwd Segment Size"] = safe(getattr(flow, "dst2src_mean_ps", 0))

        # Subflow (approx using totals)
        f["Subflow Fwd Packets"] = f["Total Fwd Packets"]
        f["Subflow Fwd Bytes"] = f["Total Length of Fwd Packets"]
        f["Subflow Bwd Packets"] = f["Total Backward Packets"]
        f["Subflow Bwd Bytes"] = f["Total Length of Bwd Packets"]

        f["Init_Win_bytes_forward"] = safe(getattr(flow, "src2dst_init_win_bytes", 0))
        f["Init_Win_bytes_backward"] = safe(getattr(flow, "dst2src_init_win_bytes", 0))
        f["act_data_pkt_fwd"] = safe(getattr(flow, "src2dst_packets", 0)) # approx
        f["min_seg_size_forward"] = 20 # approx

        f["Active Mean"] = 0
        f["Active Std"] = 0
        f["Active Max"] = 0
        f["Active Min"] = 0
        f["Idle Mean"] = 0
        f["Idle Std"] = 0
        f["Idle Max"] = 0
        f["Idle Min"] = 0

        vector = []
        for c in FEATURE_COLUMNS:
            vector.append(f.get(c, 0))

        meta = {
            "src_ip": getattr(flow, "src_ip", "unknown"),
            "dst_ip": getattr(flow, "dst_ip", "unknown"),
            "src_port": getattr(flow, "src_port", None),
            "dst_port": getattr(flow, "dst_port", None),
            "protocol": getattr(flow, "protocol", None),
            "fwd_syn_packets": safe(getattr(flow, "src2dst_syn_packets", 0)),
            "fwd_rst_packets": safe(getattr(flow, "src2dst_rst_packets", 0)),
            "fwd_fin_packets": safe(getattr(flow, "src2dst_fin_packets", 0))
        }
        
        return {"vector": vector, "meta": meta}
