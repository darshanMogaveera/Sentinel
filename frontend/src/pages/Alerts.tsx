import React, { useEffect, useState } from 'react';
import { getAlerts, getHealth } from '../api/client';
import {
  Bell,
  Search,
  Filter,
  ShieldCheck,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  ShieldAlert,
  Activity,
  Clock
} from 'lucide-react';

import {
  FEATURE_MAPPING,
  PROTOCOL_FEATURES,
  getFeatureDisplayName,
  getModelExplanationSummary
} from '../utils/explanationSummary';


/**
 * Backend timestamps are currently stored as UTC without a timezone
 * suffix, for example:
 *
 *   2026-09-11T06:46:13
 *
 * JavaScript would otherwise interpret that as local time.
 * Adding "Z" explicitly tells the browser that the value is UTC,
 * after which toLocaleDateString/toLocaleTimeString convert it
 * to the user's local timezone.
 */
function parseBackendTimestamp(timestamp: string): Date {
  if (!timestamp) {
    return new Date(NaN);
  }

  const value = String(timestamp).trim();

  if (
    value.endsWith("Z") ||
    /[+-]\d{2}:\d{2}$/.test(value)
  ) {
    return new Date(value);
  }

  return new Date(`${value}Z`);
}

function formatDate(timestamp: string): string {
  const date = parseBackendTimestamp(timestamp);

  if (Number.isNaN(date.getTime())) {
    return "Unknown date";
  }

  return date.toLocaleDateString();
}

function formatTime(timestamp: string): string {
  const date = parseBackendTimestamp(timestamp);

  if (Number.isNaN(date.getTime())) {
    return "Unknown time";
  }

  return date.toLocaleTimeString();
}

function getActualProtocol(
  protocol_raw: any
): { name: string; description: string; raw: number } {

  if (!protocol_raw) {
    return {
      name: "Protocol could not be determined",
      description: "Protocol raw values missing.",
      raw: -1
    };
  }

  if (protocol_raw.proto_tcp === 1) {
    return {
      ...FEATURE_MAPPING["proto_tcp"],
      raw: 1
    };
  }

  if (protocol_raw.proto_udp === 1) {
    return {
      ...FEATURE_MAPPING["proto_udp"],
      raw: 1
    };
  }

  if (protocol_raw.proto_icmp === 1) {
    return {
      ...FEATURE_MAPPING["proto_icmp"],
      raw: 1
    };
  }

  if (protocol_raw.proto_other === 1) {
    return {
      ...FEATURE_MAPPING["proto_other"],
      raw: 1
    };
  }

  return {
    name: "Protocol could not be determined",
    description: "No protocol was definitively observed.",
    raw: -1
  };
}

const Alerts = () => {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<Record<string, boolean>>({});
  const [limit, setLimit] = useState(20);
  const [isSystemActive, setIsSystemActive] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [fetchError, setFetchError] = useState<string | null>(null);

  const fetchAlerts = async (currentLimit: number) => {
    try {
      const res = await getAlerts(currentLimit);
      setAlerts(res.data.alerts || []);
      setStats(res.data.stats || null);
      setFetchError(null);
    } catch (err: any) {
      console.error("Failed to load alerts", err);
      setFetchError(err?.message || "Failed to load alerts from backend");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts(limit);

    getHealth()
      .then(res => {
        setIsSystemActive(
          res.data.status === 'healthy'
        );
      })
      .catch(() => {
        setIsSystemActive(false);
      });

    const interval = setInterval(() => {
      fetchAlerts(limit);
    }, 3000);

    return () => clearInterval(interval);
  }, [limit]);

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch =
      alert.source_ip.includes(searchQuery) ||
      alert.dest_ip.includes(searchQuery) ||
      alert.threat_type
        .toLowerCase()
        .includes(searchQuery.toLowerCase()) ||
      alert.alert_id
        .toLowerCase()
        .includes(searchQuery.toLowerCase());

    const matchesStatus =
      statusFilter === 'all' ||
      alert.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-500">

      {/* PAGE HEADER */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Bell className="text-[#7BBDE8]" size={24} />
              Security Alerts
            </h1>

            <div
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${isSystemActive
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                }`}
            >
              <div
                className={`w-1.5 h-1.5 rounded-full ${isSystemActive
                    ? 'bg-emerald-400 animate-pulse'
                    : 'bg-rose-400'
                  }`}
              />

              {isSystemActive
                ? 'Monitoring Active'
                : 'System Offline'}
            </div>
          </div>

          <p className="text-[#6EA2B3] mt-1 font-medium text-sm">
            Review and investigate suspicious network activity detected by Sentinel.
          </p>
        </div>
      </div>

      {fetchError && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-4 flex items-center gap-3 text-rose-300 text-sm">
          <AlertTriangle size={18} className="text-rose-400 flex-shrink-0" />
          <span>Failed to load alerts: {fetchError}</span>
        </div>
      )}

      {/* SUMMARY CARDS */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">

          <div className="glass-card p-5 border-l-2 border-l-[#49769F]">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-[#6EA2B3] text-xs font-bold uppercase tracking-wider mb-1">
                  Total Alerts
                </p>
                <h3 className="text-2xl font-bold text-white">
                  {stats.total}
                </h3>
              </div>

              <div className="p-2 bg-[#001D39]/50 rounded-lg">
                <ShieldAlert size={20} className="text-[#7BBDE8]" />
              </div>
            </div>
          </div>

          <div className="glass-card p-5 border-l-2 border-l-rose-500">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-[#6EA2B3] text-xs font-bold uppercase tracking-wider mb-1">
                  Active Alerts
                </p>
                <h3 className="text-2xl font-bold text-white">
                  {stats.active}
                </h3>
              </div>

              <div className="p-2 bg-rose-500/10 rounded-lg">
                <Activity size={20} className="text-rose-400" />
              </div>
            </div>
          </div>

          <div className="glass-card p-5 border-l-2 border-l-amber-500">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-[#6EA2B3] text-xs font-bold uppercase tracking-wider mb-1">
                  High Confidence
                </p>
                <h3 className="text-2xl font-bold text-white">
                  {stats.high_confidence}
                </h3>
              </div>

              <div className="p-2 bg-amber-500/10 rounded-lg">
                <AlertTriangle size={20} className="text-amber-400" />
              </div>
            </div>
          </div>

          <div className="glass-card p-5 border-l-2 border-l-[#7BBDE8]">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-[#6EA2B3] text-xs font-bold uppercase tracking-wider mb-1">
                  Recent Alerts (24h)
                </p>
                <h3 className="text-2xl font-bold text-white">
                  {stats.recent_24h}
                </h3>
              </div>

              <div className="p-2 bg-[#7BBDE8]/10 rounded-lg">
                <Clock size={20} className="text-[#7BBDE8]" />
              </div>
            </div>
          </div>

        </div>
      )}

      {/* RECENT ALERTS SECTION */}
      <div className="glass-card p-6">

        <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 mb-6">

          <div>
            <h2 className="text-lg font-bold text-white">
              Recent Alerts
            </h2>

            <p className="text-[#6EA2B3] text-sm mt-1">
              Latest suspicious network activity detected by Sentinel.
            </p>
          </div>

          <div className="flex gap-3 w-full md:w-auto">

            <div className="relative flex-1 md:w-64">
              <Search
                className="absolute left-3 top-1/2 -translate-y-1/2 text-[#49769F]"
                size={16}
              />

              <input
                type="text"
                placeholder="Search alerts..."
                value={searchQuery}
                onChange={(e) =>
                  setSearchQuery(e.target.value)
                }
                className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder-[#49769F] focus:outline-none focus:border-[#7BBDE8] transition-colors"
              />
            </div>

            <div className="relative flex items-center bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-sm text-white focus-within:border-[#7BBDE8] transition-colors">

              <Filter
                className="text-[#49769F] mr-2"
                size={16}
              />

              <select
                value={statusFilter}
                onChange={(e) =>
                  setStatusFilter(e.target.value)
                }
                className="bg-transparent border-none outline-none text-sm text-white appearance-none pr-4"
              >
                <option
                  value="all"
                  className="bg-[#0A4174]"
                >
                  All Status
                </option>

                <option
                  value="active"
                  className="bg-[#0A4174]"
                >
                  Active
                </option>

                <option
                  value="acknowledged"
                  className="bg-[#0A4174]"
                >
                  Acknowledged
                </option>

                <option
                  value="resolved"
                  className="bg-[#0A4174]"
                >
                  Resolved
                </option>
              </select>

            </div>
          </div>
        </div>

        <div className="overflow-x-auto rounded-xl border border-[#49769F]/20">

          <table className="w-full text-left border-collapse">

            <thead>
              <tr className="bg-[#0A4174]/40 border-b border-[#49769F]/30">

                <th className="p-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider w-32">
                  Time
                </th>

                <th className="p-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider w-24">
                  Alert ID
                </th>

                <th className="p-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider">
                  Source → Destination
                </th>

                <th className="p-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider">
                  Threat
                </th>

                <th className="p-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider w-32">
                  Confidence
                </th>

                <th className="p-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider w-24 text-right">
                  Status
                </th>

              </tr>
            </thead>

            <tbody className="text-sm">

              {loading ? (

                <tr>
                  <td
                    colSpan={6}
                    className="p-8 text-center text-[#BDD8E9] animate-pulse"
                  >
                    Loading alerts...
                  </td>
                </tr>

              ) : filteredAlerts.length > 0 ? (

                filteredAlerts.map((alert, idx) => {

                  let explanationObj: any = null;

                  try {
                    if (alert.explanation) {
                      explanationObj = JSON.parse(
                        alert.explanation
                      );
                    }
                  } catch (e) { }

                  const isExpanded =
                    expandedAlert === alert.alert_id;

                  const confidenceNum = (alert.confidence || 0) * 100;
                  const confidenceDisplay = confidenceNum % 1 === 0 ? confidenceNum.toString() : confidenceNum.toFixed(1);
                  const isHighConfidence = confidenceNum >= 80;

                  return (
                    <React.Fragment key={idx}>

                      <tr
                        onClick={() =>
                          setExpandedAlert(
                            isExpanded
                              ? null
                              : alert.alert_id
                          )
                        }
                        className={`border-b border-[#49769F]/10 hover:bg-[#0A4174]/20 transition-colors cursor-pointer ${isExpanded
                            ? 'bg-[#001D39]/30'
                            : ''
                          }`}
                      >

                        <td className="p-4 text-[#BDD8E9] whitespace-nowrap text-xs">

                          <div className="font-medium">
                            {formatDate(alert.timestamp)}
                          </div>

                          <div className="text-[#6EA2B3]">
                            {formatTime(alert.timestamp)}
                          </div>

                        </td>

                        <td className="p-4 font-mono text-xs text-[#6EA2B3]">
                          {alert.alert_id.split('-')[0]}
                        </td>

                        <td className="p-4">

                          <div className="flex items-center gap-2">

                            <span className="font-mono font-bold text-white">
                              {alert.source_ip}
                            </span>

                            <span className="text-[#49769F] text-xs">
                              →
                            </span>

                            <span className="font-mono text-sm text-[#BDD8E9]">
                              {alert.dest_ip}
                            </span>

                          </div>

                        </td>

                        <td className="p-4 text-white font-medium">
                          {alert.threat_type}
                        </td>

                        <td className="p-4">

                          <div className="flex flex-col gap-1">

                            {isHighConfidence ? (

                              <span className="text-[10px] font-bold text-amber-400 uppercase tracking-wider">
                                High Confidence
                              </span>

                            ) : (

                              <span className="text-[10px] font-bold text-[#7BBDE8] uppercase tracking-wider">
                                Moderate
                              </span>

                            )}

                            <div className="flex items-center gap-2">

                              <span
                                className={`text-lg font-bold ${isHighConfidence
                                    ? 'text-white'
                                    : 'text-[#BDD8E9]'
                                  }`}
                              >
                                {confidenceDisplay}%
                              </span>

                            </div>

                          </div>

                        </td>

                        <td className="p-4 text-right">

                          <span
                            className={`inline-flex items-center px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border ${alert.status === 'active'
                                ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                                : alert.status === 'acknowledged'
                                  ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                                  : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                              }`}
                          >
                            {alert.status || 'Unknown'}
                          </span>

                        </td>

                      </tr>

                      {isExpanded &&
                        explanationObj &&
                        explanationObj.top_features && (

                          <tr className="bg-[#001D39]/50 border-b border-[#49769F]/30 shadow-inner">

                            <td
                              colSpan={6}
                              className="p-0"
                            >

                              <div className="p-6 ml-4 border-l-2 border-[#49769F]/30 my-2">

                                <h4 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                                  Why did Sentinel flag this?
                                </h4>

                                <p className="text-sm text-[#BDD8E9] mb-6">
                                  {explanationObj.text}
                                </p>

                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

                                  {/* NETWORK OBSERVATION */}

                                  <div>

                                    <h5 className="text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-3 flex items-center gap-2">

                                      <Activity size={14} />

                                      Network Observation

                                    </h5>

                                    <div className="space-y-2">

                                      {(() => {

                                        const actualProtocol =
                                          getActualProtocol(
                                            explanationObj.protocol_raw
                                          );

                                        return (
                                          <div className="flex justify-between items-center p-3 bg-[#0A4174]/20 rounded border border-[#49769F]/20">

                                            <div>

                                              <div className="text-sm text-white font-medium">
                                                {actualProtocol.name}
                                              </div>

                                              <div className="text-xs text-[#6EA2B3] mt-0.5">
                                                {actualProtocol.description}
                                              </div>

                                            </div>

                                            <div className="font-mono text-sm text-[#7BBDE8] bg-[#001D39] px-2 py-1 rounded">
                                              {actualProtocol.raw !== -1
                                                ? Number(
                                                  actualProtocol.raw
                                                ).toFixed(2)
                                                : 'N/A'}
                                            </div>

                                          </div>
                                        );

                                      })()}

                                      {explanationObj.top_features.map(
                                        (feat: any, i: number) => {

                                          if (
                                            PROTOCOL_FEATURES.has(
                                              feat.feature
                                            ) &&
                                            feat.raw_value === 1
                                          ) {
                                            return null;
                                          }

                                          let obsMapping;

                                          if (
                                            PROTOCOL_FEATURES.has(
                                              feat.feature
                                            ) &&
                                            feat.raw_value === 0
                                          ) {

                                            obsMapping = {
                                              name:
                                                `${feat.feature
                                                  .replace(
                                                    'proto_',
                                                    ''
                                                  )
                                                  .toUpperCase()} indicator (absent)`,

                                              description:
                                                `This protocol was not used in the observed traffic.`
                                            };

                                          } else {

                                            obsMapping =
                                              FEATURE_MAPPING[
                                              feat.feature
                                              ] || {
                                                name:
                                                  feat.feature,

                                                description:
                                                  "Observed network characteristic."
                                              };

                                          }

                                          return (
                                            <div
                                              key={`obs-${i}`}
                                              className="flex justify-between items-center p-3 bg-[#0A4174]/20 rounded border border-[#49769F]/20"
                                            >

                                              <div>

                                                <div className="text-sm text-white font-medium">
                                                  {obsMapping.name}
                                                </div>

                                                <div className="text-xs text-[#6EA2B3] mt-0.5">
                                                  {obsMapping.description}
                                                </div>

                                              </div>

                                              <div className="font-mono text-sm text-[#7BBDE8] bg-[#001D39] px-2 py-1 rounded">
                                                {feat.raw_value !== undefined
                                                  ? Number(
                                                    feat.raw_value
                                                  ).toFixed(2)
                                                  : 'N/A'}
                                              </div>

                                            </div>
                                          );

                                        }
                                      )}

                                    </div>

                                  </div>

                                  {/* MODEL EXPLANATION */}

                                  <div>

                                    <h5 className="text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-3 flex items-center gap-2">

                                      <ShieldAlert size={14} />

                                      Model Explanation

                                    </h5>

                                    <div className="space-y-2">
                                      {explanationObj.top_features.length === 0 ? (
                                        <div className="flex justify-center items-center p-3 bg-[#0A4174]/20 rounded border border-[#49769F]/20 text-sm text-[#6EA2B3]">
                                          Model contribution explanation unavailable for this prediction.
                                        </div>
                                      ) : (
                                        explanationObj.top_features.map(
                                          (feat: any, i: number) => {
                                            const displayName = getFeatureDisplayName(feat);
                                            const isPositive =
                                              typeof feat?.impact === 'number' && feat.impact > 0;

                                            return (
                                              <div
                                                key={`exp-${i}`}
                                                className="flex justify-between items-center p-3 bg-[#0A4174]/20 rounded border border-[#49769F]/20"
                                              >
                                                <div className="text-sm text-white font-medium">
                                                  {displayName}
                                                </div>

                                                <div
                                                  className={`text-xs font-bold px-2 py-1 rounded border flex items-center gap-1 ${isPositive
                                                      ? 'bg-rose-500/10 border-rose-500/20 text-rose-400'
                                                      : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                                                    }`}
                                                >
                                                  {isPositive
                                                    ? 'Toward threat'
                                                    : 'Away from threat'}
                                                </div>
                                              </div>
                                            );
                                          }
                                        )
                                      )}
                                    </div>

                                    {(() => {
                                      const summary = getModelExplanationSummary(explanationObj.top_features);
                                      return (
                                        <p className="text-[10px] text-[#6EA2B3] mt-3 italic leading-relaxed">
                                          {summary.parts ? (
                                            <>
                                              {summary.parts.prefix}
                                              <strong className="font-bold text-white not-italic">
                                                {summary.parts.strongest}
                                              </strong>
                                              {summary.parts.middle}
                                              {summary.parts.weakest ? (
                                                <>
                                                  <strong className="font-bold text-white not-italic">
                                                    {summary.parts.weakest}
                                                  </strong>
                                                  {summary.parts.suffix}
                                                </>
                                              ) : null}
                                            </>
                                          ) : (
                                            summary.text
                                          )}
                                        </p>
                                      );
                                    })()}

                                  </div>

                                </div>

                                <div className="mt-6 pt-4 border-t border-[#49769F]/20">

                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();

                                      setShowTechnicalDetails({
                                        ...showTechnicalDetails,
                                        [alert.alert_id]:
                                          !showTechnicalDetails[
                                          alert.alert_id
                                          ]
                                      });
                                    }}
                                    className="flex items-center gap-2 text-xs font-bold text-[#6EA2B3] hover:text-[#7BBDE8] transition-colors uppercase tracking-wider"
                                  >

                                    {showTechnicalDetails[
                                      alert.alert_id
                                    ]
                                      ? <ChevronDown size={14} />
                                      : <ChevronRight size={14} />}

                                    Technical SHAP Details

                                  </button>

                                  {showTechnicalDetails[
                                    alert.alert_id
                                  ] && (

                                      <div className="mt-3 bg-[#0A4174]/20 p-4 rounded border border-[#49769F]/20 font-mono text-xs text-[#BDD8E9]">

                                        <table className="w-full text-left">

                                          <thead>

                                            <tr className="border-b border-[#49769F]/30 text-[#6EA2B3]">

                                              <th className="py-2 pr-4 font-normal">
                                                Feature
                                              </th>

                                              <th className="py-2 pr-4 font-normal">
                                                Raw Value
                                              </th>

                                              <th className="py-2 font-normal text-right">
                                                SHAP Impact
                                              </th>

                                            </tr>

                                          </thead>

                                          <tbody>

                                            {explanationObj.top_features.map(
                                              (feat: any, i: number) => {

                                                const hasImpact =
                                                  typeof feat?.impact === 'number';

                                                const isPositive =
                                                  hasImpact && feat.impact > 0;

                                                const hasRaw =
                                                  typeof feat?.raw_value === 'number';

                                                return (
                                                  <tr
                                                    key={i}
                                                    className="border-b border-[#49769F]/10 last:border-0 hover:bg-[#001D39]/30"
                                                  >

                                                    <td className="py-2 pr-4 text-white">
                                                      {feat?.feature || 'Unknown feature'}
                                                    </td>

                                                    <td className="py-2 pr-4">
                                                      {hasRaw
                                                        ? Number(
                                                          feat.raw_value
                                                        ).toFixed(4)
                                                        : 'N/A'}
                                                    </td>

                                                    <td
                                                      className={`py-2 text-right ${isPositive
                                                          ? 'text-rose-400'
                                                          : hasImpact
                                                            ? 'text-emerald-400'
                                                            : 'text-[#6EA2B3]'
                                                        }`}
                                                    >
                                                      {hasImpact
                                                        ? `${isPositive ? '+' : ''}${feat.impact.toFixed(4)}`
                                                        : 'N/A'}
                                                    </td>

                                                  </tr>
                                                );

                                              }
                                            )}

                                          </tbody>

                                        </table>

                                      </div>

                                    )}

                                </div>

                              </div>

                            </td>

                          </tr>

                        )}

                    </React.Fragment>
                  );
                })

              ) : (

                <tr>

                  <td
                    colSpan={6}
                    className="p-16 text-center"
                  >

                    <div className="flex flex-col items-center justify-center max-w-sm mx-auto">

                      <div className="w-16 h-16 bg-[#001D39] rounded-full flex items-center justify-center mb-4 border border-[#49769F]/30">

                        <ShieldCheck
                          size={32}
                          className="text-emerald-400"
                        />

                      </div>

                      <h3 className="text-xl font-bold text-white mb-2">
                        No threats detected
                      </h3>

                      <p className="text-[#BDD8E9] text-sm text-center leading-relaxed">
                        Sentinel has not recorded any alerts matching your criteria. Your network is currently secure.
                      </p>

                    </div>

                  </td>

                </tr>

              )}

            </tbody>

          </table>

          {!loading &&
            alerts.length > 0 &&
            alerts.length >= limit && (

              <div className="p-4 border-t border-[#49769F]/30 flex justify-center bg-[#0A4174]/20">

                <button
                  onClick={() =>
                    setLimit(limit + 20)
                  }
                  className="glass-button px-6 py-2 text-sm font-bold text-white hover:text-white"
                >
                  Load More Alerts
                </button>

              </div>

            )}

        </div>

      </div>

    </div>
  );
};

export default Alerts;