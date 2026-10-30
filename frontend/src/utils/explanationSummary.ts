/**
 * Feature mapping and dynamic model explanation summary for Security Alerts.
 */

export const FEATURE_MAPPING: Record<string, { name: string; description: string }> = {
  // Protocol indicators
  "proto_tcp": { name: "TCP protocol", description: "The communication used the Transmission Control Protocol (TCP)." },
  "proto_udp": { name: "UDP protocol", description: "The communication used the User Datagram Protocol (UDP)." },
  "proto_icmp": { name: "ICMP protocol", description: "The communication used the Internet Control Message Protocol (ICMP)." },
  "proto_other": { name: "Other protocol", description: "The communication used an uncommon network protocol." },

  // CIC-IDS2017 Production Features
  "Destination Port": { name: "Destination Port", description: "Destination transport port targeted by connection." },
  "Flow Duration": { name: "Flow Duration (μs)", description: "Total duration of the bidirectional network flow in microseconds." },
  "Total Fwd Packets": { name: "Total Forward Packets", description: "Number of packets transmitted in the forward (source to destination) direction." },
  "Total Backward Packets": { name: "Total Backward Packets", description: "Number of packets received in the backward (destination to source) direction." },
  "Total Length of Fwd Packets": { name: "Forward Payload Bytes", description: "Total bytes of payload sent in forward packets." },
  "Total Length of Bwd Packets": { name: "Backward Payload Bytes", description: "Total bytes of payload sent in backward packets." },
  "Fwd Packet Length Max": { name: "Max Forward Packet Size", description: "Maximum packet length observed in forward direction." },
  "Fwd Packet Length Min": { name: "Min Forward Packet Size", description: "Minimum packet length observed in forward direction." },
  "Fwd Packet Length Mean": { name: "Mean Forward Packet Size", description: "Mean packet length observed in forward direction." },
  "Fwd Packet Length Std": { name: "Forward Packet Size StdDev", description: "Standard deviation of packet lengths in forward direction." },
  "Bwd Packet Length Max": { name: "Max Backward Packet Size", description: "Maximum packet length observed in backward direction." },
  "Bwd Packet Length Min": { name: "Min Backward Packet Size", description: "Minimum packet length observed in backward direction." },
  "Bwd Packet Length Mean": { name: "Mean Backward Packet Size", description: "Mean packet length observed in backward direction." },
  "Bwd Packet Length Std": { name: "Backward Packet Size StdDev", description: "Standard deviation of packet lengths in backward direction." },
  "Flow Bytes/s": { name: "Flow Byte Rate", description: "Transmission rate in bytes per second across the flow." },
  "Flow Packets/s": { name: "Flow Packet Rate", description: "Transmission rate in packets per second across the flow." },
  "Flow IAT Mean": { name: "Mean Inter-Arrival Time", description: "Mean time between consecutive packets in microseconds." },
  "Flow IAT Std": { name: "Inter-Arrival Time StdDev", description: "Standard deviation of packet inter-arrival times in microseconds." },
  "Flow IAT Max": { name: "Max Inter-Arrival Time", description: "Maximum time between consecutive packets in microseconds." },
  "Flow IAT Min": { name: "Min Inter-Arrival Time", description: "Minimum time between consecutive packets in microseconds." },
  "Fwd IAT Total": { name: "Total Forward IAT", description: "Total time between packets in forward direction." },
  "Fwd IAT Mean": { name: "Mean Forward IAT", description: "Mean time between forward packets." },
  "Fwd IAT Std": { name: "Forward IAT StdDev", description: "Standard deviation of forward packet arrival times." },
  "Fwd IAT Max": { name: "Max Forward IAT", description: "Maximum time between forward packets." },
  "Fwd IAT Min": { name: "Min Forward IAT", description: "Minimum time between forward packets." },
  "Bwd IAT Total": { name: "Total Backward IAT", description: "Total time between packets in backward direction." },
  "Bwd IAT Mean": { name: "Mean Backward IAT", description: "Mean time between backward packets." },
  "Bwd IAT Std": { name: "Backward IAT StdDev", description: "Standard deviation of backward packet arrival times." },
  "Bwd IAT Max": { name: "Max Backward IAT", description: "Maximum time between backward packets." },
  "Bwd IAT Min": { name: "Min Backward IAT", description: "Minimum time between backward packets." },
  "Fwd PSH Flags": { name: "Forward PSH Flags", description: "Number of forward packets with TCP PSH flag set." },
  "Fwd URG Flags": { name: "Forward URG Flags", description: "Number of forward packets with TCP URG flag set." },
  "Fwd Header Length": { name: "Forward Header Length", description: "Total bytes of TCP/IP headers in forward direction." },
  "Bwd Header Length": { name: "Backward Header Length", description: "Total bytes of TCP/IP headers in backward direction." },
  "Fwd Packets/s": { name: "Forward Packet Rate", description: "Rate of packets per second in forward direction." },
  "Bwd Packets/s": { name: "Backward Packet Rate", description: "Rate of packets per second in backward direction." },
  "Min Packet Length": { name: "Min Packet Length", description: "Minimum packet size observed across bidirectional flow." },
  "Max Packet Length": { name: "Max Packet Length", description: "Maximum packet size observed across bidirectional flow." },
  "Packet Length Mean": { name: "Mean Packet Length", description: "Average packet size observed across bidirectional flow." },
  "Packet Length Std": { name: "Packet Length StdDev", description: "Standard deviation of packet size across bidirectional flow." },
  "Packet Length Variance": { name: "Packet Length Variance", description: "Variance of packet size across bidirectional flow." },
  "FIN Flag Count": { name: "FIN Flag Count", description: "Number of packets with FIN flag set." },
  "SYN Flag Count": { name: "SYN Flag Count", description: "Number of packets with SYN flag set." },
  "RST Flag Count": { name: "RST Flag Count", description: "Number of packets with RST flag set." },
  "PSH Flag Count": { name: "PSH Flag Count", description: "Number of packets with PSH flag set." },
  "ACK Flag Count": { name: "ACK Flag Count", description: "Number of packets with ACK flag set." },
  "URG Flag Count": { name: "URG Flag Count", description: "Number of packets with URG flag set." },
  "CWE Flag Count": { name: "CWE Flag Count", description: "Number of packets with CWE/CWR flag set." },
  "ECE Flag Count": { name: "ECE Flag Count", description: "Number of packets with ECE flag set." },
  "Down/Up Ratio": { name: "Download/Upload Ratio", description: "Ratio of received bytes to transmitted bytes." },
  "Average Packet Size": { name: "Average Packet Size", description: "Average bidirectional packet size in bytes." },
  "Avg Fwd Segment Size": { name: "Avg Forward Segment Size", description: "Average TCP segment size sent forward." },
  "Avg Bwd Segment Size": { name: "Avg Backward Segment Size", description: "Average TCP segment size received backward." },
  "Subflow Fwd Packets": { name: "Subflow Forward Packets", description: "Number of packets in subflow forward direction." },
  "Subflow Fwd Bytes": { name: "Subflow Forward Bytes", description: "Number of bytes in subflow forward direction." },
  "Subflow Bwd Packets": { name: "Subflow Backward Packets", description: "Number of packets in subflow backward direction." },
  "Subflow Bwd Bytes": { name: "Subflow Backward Bytes", description: "Number of bytes in subflow backward direction." },
  "Init_Win_bytes_forward": { name: "Initial TCP Window (Fwd)", description: "Initial TCP window size advertised in forward direction." },
  "Init_Win_bytes_backward": { name: "Initial TCP Window (Bwd)", description: "Initial TCP window size advertised in backward direction." },
  "act_data_pkt_fwd": { name: "Forward Data Packets", description: "Count of forward packets carrying at least 1 byte of TCP payload." },
  "min_seg_size_forward": { name: "Min Segment Size (Fwd)", description: "Minimum segment size observed in forward direction." },
  "Active Mean": { name: "Mean Active Time", description: "Mean time a flow was active before becoming idle." },
  "Active Std": { name: "Active Time StdDev", description: "Standard deviation of flow active time." },
  "Active Max": { name: "Max Active Time", description: "Maximum time a flow was active." },
  "Active Min": { name: "Min Active Time", description: "Minimum time a flow was active." },
  "Idle Mean": { name: "Mean Idle Time", description: "Mean time a flow was idle before becoming active." },
  "Idle Std": { name: "Idle Time StdDev", description: "Standard deviation of flow idle time." },
  "Idle Max": { name: "Max Idle Time", description: "Maximum time a flow was idle." },
  "Idle Min": { name: "Min Idle Time", description: "Minimum time a flow was idle." }
};

export const PROTOCOL_FEATURES = new Set([
  "proto_tcp",
  "proto_udp",
  "proto_icmp",
  "proto_other"
]);

/**
 * Returns the human-readable display name for a feature, matching the
 * labels displayed in the Model Explanation section.
 */
export const getFeatureDisplayName = (feat: any): string => {
  if (!feat || typeof feat !== 'object') {
    return 'Unknown feature';
  }
  const rawName = typeof feat.feature === 'string' ? feat.feature.trim() : '';
  if (!rawName) {
    return 'Unknown feature';
  }
  if (PROTOCOL_FEATURES.has(rawName) && feat.raw_value === 0) {
    return `${rawName.replace('proto_', '').toUpperCase()} indicator (absent)`;
  }
  const mapped = FEATURE_MAPPING[rawName];
  return mapped?.name || rawName;
};

/**
 * Validates that an item is a valid feature object with a non-empty name
 * and a finite numeric SHAP contribution impact.
 */
export const isValidFeature = (feat: any): boolean => {
  if (!feat || typeof feat !== 'object') return false;
  if (typeof feat.feature !== 'string' || !feat.feature.trim()) return false;
  if (typeof feat.impact !== 'number' || !Number.isFinite(feat.impact)) return false;
  return true;
};

/**
 * Checks whether a feature's SHAP contribution is strictly positive toward
 * the threat/PortScan class. Excludes zero and negative contributions entirely.
 */
export const isPositiveContribution = (feat: any): boolean => {
  return isValidFeature(feat) && feat.impact > 0;
};

export interface EligibleFeature {
  feature: string;
  name: string;
  impact: number;
  index: number;
}

export interface ModelExplanationSummaryResult {
  text: string;
  mostInfluentialFeature: string | null;
  leastInfluentialFeature: string | null;
  eligibleCount: number;
  parts: {
    prefix: string;
    strongest: string;
    middle: string;
    weakest?: string;
    suffix: string;
  } | null;
}

/**
 * Generates the dynamic model explanation summary from the top displayed features.
 *
 * Rules:
 * 1. Considers ONLY features with strictly positive SHAP impact (> 0).
 * 2. Restricts evaluation to the top five displayed features.
 * 3. Identifies strongest and weakest positive contributors deterministically.
 * 4. When >= 2 eligible features:
 *    "The strongest contributing feature toward the threat classification was **{mostInfluentialFeature}**, while **{leastInfluentialFeature}** had the smallest positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions."
 * 5. When 1 eligible feature:
 *    "The strongest contributing feature toward the threat classification was **{mostInfluentialFeature}**, which was the only positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions."
 * 6. When 0 eligible features:
 *    "No positive feature contributions toward the threat classification are available for this alert. See Technical SHAP Details below for any available contribution data."
 */
export function getModelExplanationSummary(topFeatures: any): ModelExplanationSummaryResult {
  const rawList = Array.isArray(topFeatures) ? topFeatures.slice(0, 5) : [];

  const eligible: EligibleFeature[] = [];
  for (let i = 0; i < rawList.length; i++) {
    const feat = rawList[i];
    if (isPositiveContribution(feat)) {
      eligible.push({
        feature: feat.feature.trim(),
        name: getFeatureDisplayName(feat),
        impact: feat.impact,
        index: i
      });
    }
  }

  // If no positive contributions exist
  if (eligible.length === 0) {
    return {
      text: "No positive feature contributions toward the threat classification are available for this alert. See Technical SHAP Details below for any available contribution data.",
      mostInfluentialFeature: null,
      leastInfluentialFeature: null,
      eligibleCount: 0,
      parts: null
    };
  }

  // Sort deterministically:
  // Primary: impact descending (highest positive contribution first)
  // Secondary: alphabetical by feature display name
  // Tertiary: original display index ascending
  eligible.sort((a, b) => {
    if (b.impact !== a.impact) {
      return b.impact - a.impact;
    }
    const nameDiff = a.name.localeCompare(b.name);
    if (nameDiff !== 0) {
      return nameDiff;
    }
    return a.index - b.index;
  });

  const most = eligible[0].name;

  if (eligible.length === 1) {
    return {
      text: `The strongest contributing feature toward the threat classification was **${most}**, which was the only positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions.`,
      mostInfluentialFeature: most,
      leastInfluentialFeature: null,
      eligibleCount: 1,
      parts: {
        prefix: "The strongest contributing feature toward the threat classification was ",
        strongest: most,
        middle: ", which was the only positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions.",
        suffix: ""
      }
    };
  }

  const least = eligible[eligible.length - 1].name;

  return {
    text: `The strongest contributing feature toward the threat classification was **${most}**, while **${least}** had the smallest positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions.`,
    mostInfluentialFeature: most,
    leastInfluentialFeature: least,
    eligibleCount: eligible.length,
    parts: {
      prefix: "The strongest contributing feature toward the threat classification was ",
      strongest: most,
      middle: ", while ",
      weakest: least,
      suffix: " had the smallest positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions."
    }
  };
}
