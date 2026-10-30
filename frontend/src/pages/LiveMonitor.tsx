import { useEffect, useState } from 'react';
import {
  Play,
  Square,
  Activity,
  ShieldAlert,
  Cpu,
  AlertTriangle,
  CheckCircle,
  Smartphone
} from 'lucide-react';
import {
  getLiveStatus,
  getLiveDevices,
  startLiveCapture,
  stopLiveCapture,
  runLiveSimulation,
  getLiveRunStats
} from '../api/client';

type NetworkInterface = {
  name: string;
  label: string;
  description?: string;
};

const LiveMonitor = () => {
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [interfaceName, setInterfaceName] = useState('');
  const [interfacesLoading, setInterfacesLoading] = useState(true);

  const [actionLoading, setActionLoading] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  type SimMode = 'single' | 'range';
  const [simMode, setSimMode] = useState<SimMode>('single');
  const [rangeStart, setRangeStart] = useState<number>(12340);
  const [rangeEnd, setRangeEnd] = useState<number>(12349);
  const [validationError, setValidationError] = useState<string | null>(null);

  const [simConfig, setSimConfig] = useState({
    protocol: 'UDP',
    dest_ip: '127.0.0.1',
    dest_port: 12345,
    num_connections: 1,
    packets_per_connection: 5,
    payload_size: 64,
    delay_between_packets: 0.1,
    delay_between_connections: 0.5
  });

  const [apiError, setApiError] = useState<string | null>(null);

  const [devices, setDevices] = useState<any[]>([]);
  const [deviceLabels, setDeviceLabels] = useState<Record<string, string>>({});
  const [simRunId, setSimRunId] = useState<string | null>(null);
  const [simStats, setSimStats] = useState<any | null>(null);

  // ---------------------------------------------------------
  // Fetch available network interfaces
  // ---------------------------------------------------------
  const fetchInterfaces = async () => {
    try {
      setInterfacesLoading(true);

      const response = await fetch(
        'http://localhost:5000/api/live/interfaces'
      );

      if (!response.ok) {
        throw new Error('Failed to fetch network interfaces.');
      }

      const data = await response.json();
      const availableInterfaces: NetworkInterface[] =
        data.interfaces || [];

      setInterfaces(availableInterfaces);

      if (availableInterfaces.length > 0) {
        const savedInterface = localStorage.getItem('sentinel_selected_interface');
        const matchSaved = savedInterface && availableInterfaces.find((i) => i.name === savedInterface);

        setInterfaceName((prev) => {
          if (prev && availableInterfaces.some((i) => i.name === prev)) {
            return prev;
          }
          if (matchSaved) {
            return matchSaved.name;
          }
          const loopback = availableInterfaces.find((i) =>
            /loopback/i.test(`${i.label} ${i.name}`)
          );
          const preferredInterface = availableInterfaces.find((iface) =>
            /wi[- ]?fi|wireless|wlan/i.test(`${iface.label} ${iface.description || ''}`)
          );
          return (loopback || preferredInterface || availableInterfaces[0]).name;
        });
      } else {
        setError('No network interfaces were detected.');
      }
    } catch (err) {
      console.error('Interface discovery failed:', err);

      setError(
        'Could not detect network interfaces. Make sure the backend is running.'
      );
    } finally {
      setInterfacesLoading(false);
    }
  };

  // ---------------------------------------------------------
  // Fetch live monitoring status and devices
  // ---------------------------------------------------------
  const fetchStatus = async () => {
    try {
      const res = await getLiveStatus();

      setStatus(res.data);
      // Only update interface name from backend if capture is running AND the
      // user has no selection yet. Do NOT overwrite a user-chosen interface
      // because that causes the dropdown to silently revert on every status poll.
      if (res.data?.running && res.data?.interface && !interfaceName) {
        setInterfaceName(res.data.interface);
      }
      if (res.data?.stats?.last_error) {
        setError(`Capture error: ${res.data.stats.last_error}`);
      } else if (res.data?.error) {
        setError(res.data.error);
      } else {
        setError(null);
      }

      const devRes = await getLiveDevices();
      setDevices(devRes.data.devices || []);
    } catch (err: any) {
      if (err.response && err.response.status === 503) {
        setStatus({
          running: false,
          stats: null
        });
        setError(null);
      } else {
        setError(
          'Failed to fetch live monitoring status.'
        );
      }
    } finally {
      setLoading(false);
    }
  };

  // ---------------------------------------------------------
  // Initial loading + status polling
  // ---------------------------------------------------------
  useEffect(() => {
    fetchInterfaces();
    fetchStatus();

    const interval = setInterval(
      fetchStatus,
      2000
    );

    return () => clearInterval(interval);
  }, []);

  // ---------------------------------------------------------
  // Start capture
  // ---------------------------------------------------------
  const handleStart = async () => {
    if (!interfaceName) return;

    setActionLoading(true);
    setError(null);

    try {
      await startLiveCapture(interfaceName);
      await fetchStatus();
    } catch (err: any) {
      setError(
        err.response?.data?.error ||
        'Failed to start capture.'
      );
    } finally {
      setActionLoading(false);
    }
  };

  // ---------------------------------------------------------
  // Stop capture
  // ---------------------------------------------------------
  const handleStop = async () => {
    setActionLoading(true);

    try {
      await stopLiveCapture();
      await fetchStatus();
    } catch (err: any) {
      setError(
        'Failed to stop capture.'
      );
    } finally {
      setActionLoading(false);
    }
  };

  // ---------------------------------------------------------
  // Run traffic simulation
  // ---------------------------------------------------------
  const handleSimulate = async () => {
    if (isSubmitting || isSimActive || !status?.running) return;

    setValidationError(null);
    setApiError(null);

    // 1. Destination IP validation: must be localhost/loopback address
    const ip = (simConfig.dest_ip || '').trim();
    if (!ip) {
      setValidationError('Destination IP is required.');
      return;
    }
    const isLoopback =
      ip === '127.0.0.1' ||
      ip.toLowerCase() === 'localhost' ||
      ip === '::1' ||
      ip.startsWith('127.');
    if (!isLoopback) {
      setValidationError("Destination must be a valid localhost/loopback address (127.0.0.1).");
      return;
    }

    // Backend strictly accepts '127.0.0.1'
    const targetDestIp = (ip.toLowerCase() === 'localhost' || ip.startsWith('127.')) ? '127.0.0.1' : ip;

    // 2. Protocol validation
    const proto = (simConfig.protocol || '').toUpperCase();
    if (proto !== 'TCP' && proto !== 'UDP') {
      setValidationError("Protocol must be either 'TCP' or 'UDP'.");
      return;
    }

    // 3. Port / Range validation
    const requestPayload: any = {
      dest_ip: targetDestIp,
      protocol: proto,
      num_connections: Number(simConfig.num_connections) || 1,
      packets_per_connection: Number(simConfig.packets_per_connection) || 1,
      payload_size: Number(simConfig.payload_size) || 0,
      delay_between_packets: Number(simConfig.delay_between_packets) || 0.0,
      delay_between_connections: Number(simConfig.delay_between_connections) || 0.0
    };

    if (simMode === 'single') {
      const p = Number(simConfig.dest_port);
      if (isNaN(p) || !Number.isInteger(p) || p < 1 || p > 65535) {
        setValidationError('Destination port must be an integer between 1 and 65535.');
        return;
      }
      requestPayload.dest_port = p;
    } else {
      const s = Number(rangeStart);
      const e = Number(rangeEnd);
      if (isNaN(s) || !Number.isInteger(s) || s < 1 || s > 65535) {
        setValidationError('Start port must be an integer between 1 and 65535.');
        return;
      }
      if (isNaN(e) || !Number.isInteger(e) || e < 1 || e > 65535) {
        setValidationError('End port must be an integer between 1 and 65535.');
        return;
      }
      if (s > e) {
        setValidationError(`End port (${e}) must be greater than or equal to start port (${s}).`);
        return;
      }
      const count = e - s + 1;
      if (count > 11) {
        setValidationError(`Port range (${count} ports) exceeds the backend maximum of 11 ports.`);
        return;
      }
      if (count < 1) {
        setValidationError('At least one destination port must be specified.');
        return;
      }

      requestPayload.port_range_start = s;
      requestPayload.port_range_end = e;
    }

    setIsSubmitting(true);
    setSimStats(null);
    setSimRunId(null);

    try {
      const res = await runLiveSimulation(requestPayload);
      const runId: string | undefined = res.data?.run_id;
      if (runId) {
        setSimRunId(runId);
      }
      await fetchStatus();
    } catch (err: any) {
      setApiError(
        err.response?.data?.error ||
        err.message ||
        'Simulation failed to start'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  // Poll the specific simulation run's stats
  useEffect(() => {
    if (!simRunId) return;
    let active = true;
    const pollRunStats = async () => {
      try {
        const res = await getLiveRunStats(simRunId);
        const data = res.data;
        if (active && data?.stats) {
          setSimStats(data.stats);
          // Stop polling when simulation is done
          if (data.stats?.simulation_state === 'COMPLETED') {
            active = false;
          }
        }
      } catch {
        // ignore poll errors
      }
    };
    pollRunStats();
    const iv = setInterval(pollRunStats, 1000);
    return () => { active = false; clearInterval(iv); };
  }, [simRunId]);

  // ---------------------------------------------------------
  // Simulator presets
  // ---------------------------------------------------------
  const applyPreset = (preset: string) => {
    setValidationError(null);
    setApiError(null);

    if (preset === 'normal') {
      setSimMode('single');
      setSimConfig((prev) => ({
        ...prev,
        protocol: 'UDP',
        dest_ip: '127.0.0.1',
        dest_port: 12345,
        num_connections: 3,
        packets_per_connection: 5,
        payload_size: 64,
        delay_between_packets: 0.1,
        delay_between_connections: 0.5
      }));
    } else if (preset === 'high_rate') {
      setSimMode('single');
      setSimConfig((prev) => ({
        ...prev,
        protocol: 'UDP',
        dest_ip: '127.0.0.1',
        dest_port: 12345,
        num_connections: 1,
        packets_per_connection: 1000,
        payload_size: 1024,
        delay_between_packets: 0.0,
        delay_between_connections: 0.5
      }));
    } else if (preset === 'connection_burst') {
      setSimMode('single');
      setSimConfig((prev) => ({
        ...prev,
        protocol: 'TCP',
        dest_ip: '127.0.0.1',
        dest_port: 12345,
        num_connections: 200,
        packets_per_connection: 1,
        payload_size: 64,
        delay_between_packets: 0.0,
        delay_between_connections: 0.0
      }));
    } else if (preset === 'port_scan') {
      setSimMode('range');
      setRangeStart(12340);
      setRangeEnd(12349);
      setSimConfig((prev) => ({
        ...prev,
        protocol: 'TCP',
        dest_ip: '127.0.0.1',
        payload_size: 0,
        num_connections: 1,
        packets_per_connection: 1,
        delay_between_packets: 0.0,
        delay_between_connections: 0.0
      }));
    }
  };

  // ---------------------------------------------------------
  // Loading state
  // ---------------------------------------------------------
  if (loading && !status) {
    return (
      <div className="glass-card p-8 text-center text-[#BDD8E9] animate-pulse">
        Loading Live Monitor...
      </div>
    );
  }

  const isRunning = status?.running;

  const stats = status?.stats || null;
  const hasActiveRun = !!status?.run_id;

  // Use dedicated simStats (from run_id polling) when available;
  // fall back to general status stats for live monitoring display.
  const activeSimStats = simStats || stats;

  const displayStats =
    activeSimStats || {
      total_packets: 0,
      flushed_flows: 0,
      predictions: 0,
      alerts: 0,
      inference_errors: 0
    };

  const simState =
    (simRunId ? simStats?.simulation_state : stats?.simulation_state) ||
    'IDLE';

  const isSimActive =
    isRunning &&
    (
      simState === 'RUNNING' ||
      simState === 'PROCESSING'
    );

  const targetPortsCount =
    isNaN(rangeStart) || isNaN(rangeEnd) ? 0 : Math.max(0, rangeEnd - rangeStart + 1);

  let displayMessage = '';

  if (validationError) {
    displayMessage = validationError;
  } else if (apiError) {
    displayMessage = apiError;
  } else if (isSubmitting) {
    displayMessage = 'Starting simulation request...';
  } else if (isSimActive && simState === 'RUNNING') {
    displayMessage = 'Generating controlled traffic...';
  } else if (isSimActive && simState === 'PROCESSING') {
    displayMessage = 'Finishing flow aggregation and model inference...';
  } else if (isRunning && simState === 'COMPLETED') {
    displayMessage = 'Simulation completed successfully.';
  } else if (isRunning && (!hasActiveRun || simState === 'IDLE')) {
    displayMessage = 'Ready to start a traffic simulation.';
  }

  const showSimStats =
    !!simRunId ||
    hasActiveRun ||
    (
      isRunning &&
      simState !== 'IDLE'
    );

  // Friendly name for the currently selected interface.
  const selectedInterfaceLabel =
    interfaces.find(
      (iface) =>
        iface.name === interfaceName
    )?.label ||
    interfaceName;

  return (
    <div className="space-y-6 animate-in fade-in duration-500">

      {/* =====================================================
          TOP SECTION
      ===================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Capture Controls */}
        <div className="glass-card p-6 flex flex-col justify-between">

          <div>

            <div className="flex items-center gap-3 mb-6">

              <div
                className={`w-3 h-3 rounded-full ${isRunning
                    ? 'bg-emerald-400 shadow-[0_0_10px_#34d399] animate-pulse'
                    : 'bg-slate-500'
                  }`}
              />

              <h2 className="text-xl font-bold text-white">
                Capture Controls
              </h2>

            </div>

            <div className="space-y-4">

              {/* Network Interface */}
              <div>

                <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-2">
                  Network Interface
                </label>

                <select
                  value={interfaceName}
                  onChange={(e) => {
                    setInterfaceName(e.target.value);
                    localStorage.setItem('sentinel_selected_interface', e.target.value);
                  }}
                  disabled={
                    isRunning ||
                    actionLoading ||
                    interfacesLoading
                  }
                  className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-[#7BBDE8] disabled:opacity-50 transition-colors"
                >

                  {interfacesLoading ? (

                    <option value="">
                      Detecting network interfaces...
                    </option>

                  ) : interfaces.length === 0 ? (

                    <option value="">
                      No interfaces detected
                    </option>

                  ) : (

                    interfaces.map((iface) => (

                      <option
                        key={iface.name}
                        value={iface.name}
                      >
                        {iface.label}
                      </option>

                    ))

                  )}

                </select>

                <p className="text-xs text-[#6EA2B3] mt-2">
                  Sentinel automatically detects available
                  network interfaces.
                </p>

              </div>

              {/* Error */}
              {error && (

                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-start gap-2">

                  <AlertTriangle
                    size={16}
                    className="text-red-400 mt-0.5 flex-shrink-0"
                  />

                  <p className="text-sm text-red-200">
                    {error}
                  </p>

                </div>

              )}

            </div>

          </div>

          {/* Start / Stop */}
          <div className="mt-8 flex gap-4">

            {!isRunning ? (

              <button
                onClick={handleStart}
                disabled={
                  actionLoading ||
                  !interfaceName ||
                  interfacesLoading
                }
                className="flex-1 bg-gradient-to-r from-emerald-500/20 to-emerald-400/10 hover:from-emerald-500/30 hover:to-emerald-400/20 border border-emerald-500/40 hover:border-emerald-400/60 text-emerald-300 font-bold py-3 px-4 rounded-xl flex items-center justify-center gap-2 transition-all disabled:opacity-50"
              >

                <Play size={18} />

                <span>
                  START CAPTURE
                </span>

              </button>

            ) : (

              <button
                onClick={handleStop}
                disabled={
                  actionLoading ||
                  isSimActive
                }
                className="flex-1 bg-gradient-to-r from-red-500/20 to-red-400/10 hover:from-red-500/30 hover:to-red-400/20 border border-red-500/40 hover:border-red-400/60 text-red-300 font-bold py-3 px-4 rounded-xl flex items-center justify-center gap-2 transition-all disabled:opacity-50"
              >

                <Square size={18} />

                <span>
                  STOP CAPTURE
                </span>

              </button>

            )}

          </div>

        </div>


        {/* Live Status Overview */}
        <div className="lg:col-span-2 glass-card p-8 relative overflow-hidden flex flex-col justify-center">

          {isRunning && (
            <div className="absolute -right-20 -top-20 w-64 h-64 bg-[#7BBDE8]/10 rounded-full blur-3xl animate-pulse" />
          )}

          <div className="relative z-10 flex flex-col items-center justify-center text-center">

            {isRunning ? (

              <>

                <div className="w-20 h-20 bg-emerald-500/10 border border-emerald-500/30 rounded-full flex items-center justify-center mb-6 relative">

                  <div className="absolute inset-0 border-2 border-emerald-400/50 rounded-full animate-ping opacity-20" />

                  <Activity
                    size={32}
                    className="text-emerald-400"
                  />

                </div>

                <h1 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-white to-emerald-200 tracking-tight mb-2">
                  MONITORING ACTIVE
                </h1>

                <p className="text-lg text-[#BDD8E9] font-medium">

                  Capturing packets on{' '}

                  <span className="text-white font-bold">
                    {selectedInterfaceLabel}
                  </span>

                </p>

              </>

            ) : (

              <>

                <div className="w-20 h-20 bg-slate-800/50 border border-slate-700 rounded-full flex items-center justify-center mb-6">

                  <Square
                    size={32}
                    className="text-slate-400"
                  />

                </div>

                <h1 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-slate-200 to-slate-500 tracking-tight mb-2">
                  CAPTURE STOPPED
                </h1>

                <p className="text-lg text-slate-400 font-medium">
                  System is currently idle. Start capture to monitor traffic.
                </p>

              </>

            )}

          </div>

        </div>

      </div>


      {/* =====================================================
          TRAFFIC SIMULATOR
      ===================================================== */}
      <div className="glass-card p-6 mt-6">

        <div className="flex items-center gap-3 mb-6">

          <Activity
            size={20}
            className="text-[#7BBDE8]"
          />

          <h2 className="text-xl font-bold text-white">
            CUSTOM TRAFFIC SIMULATOR
          </h2>

        </div>


        {/* Presets */}
        <div className="flex flex-wrap items-center gap-2 mb-6">

          <span className="text-xs font-bold text-[#6EA2B3] uppercase tracking-wider self-center mr-2">
            Presets:
          </span>

          <button
            type="button"
            onClick={() =>
              applyPreset('normal')
            }
            className={`glass-button px-3 py-1.5 text-xs font-bold transition-all ${
              simMode === 'single' && simConfig.protocol === 'UDP' && simConfig.num_connections === 3
                ? 'border-[#7BBDE8]/60 bg-[#0A4174]/60 text-white'
                : ''
            }`}
          >
            Normal
          </button>

          <button
            type="button"
            onClick={() =>
              applyPreset('high_rate')
            }
            className={`glass-button px-3 py-1.5 text-xs font-bold transition-all ${
              simMode === 'single' && simConfig.protocol === 'UDP' && simConfig.packets_per_connection === 1000
                ? 'border-[#7BBDE8]/60 bg-[#0A4174]/60 text-white'
                : ''
            }`}
          >
            High Rate (UDP)
          </button>

          <button
            type="button"
            onClick={() =>
              applyPreset('connection_burst')
            }
            className={`glass-button px-3 py-1.5 text-xs font-bold transition-all ${
              simMode === 'single' && simConfig.protocol === 'TCP' && simConfig.num_connections === 200
                ? 'border-[#7BBDE8]/60 bg-[#0A4174]/60 text-white'
                : ''
            }`}
          >
            Connection Burst (TCP)
          </button>

          <button
            type="button"
            onClick={() =>
              applyPreset('port_scan')
            }
            className={`glass-button px-3 py-1.5 text-xs font-bold transition-all ${
              simMode === 'range' && simConfig.protocol === 'TCP' && rangeStart === 12340 && rangeEnd === 12349
                ? 'border-rose-400 bg-rose-500/20 text-rose-200 shadow-[0_0_12px_rgba(244,63,94,0.3)]'
                : 'border-rose-500/40 text-rose-300 hover:border-rose-400 hover:text-white'
            }`}
          >
            Port Scan (TCP SYN)
          </button>

        </div>

        {/* Mode Selector */}
        <div className="flex flex-wrap items-center justify-between gap-4 mb-6 pb-4 border-b border-[#49769F]/20">
          <div className="flex items-center gap-3">
            <span className="text-xs font-bold text-[#6EA2B3] uppercase tracking-wider">
              Simulation Mode:
            </span>
            <div className="inline-flex rounded-lg bg-[#001D39]/80 p-1 border border-[#49769F]/30">
              <button
                type="button"
                onClick={() => {
                  setSimMode('single');
                  setValidationError(null);
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all ${
                  simMode === 'single'
                    ? 'bg-[#0A4174] text-white shadow-[0_0_10px_rgba(123,189,232,0.3)] border border-[#7BBDE8]/40'
                    : 'text-[#6EA2B3] hover:text-white'
                }`}
              >
                Single Port
              </button>
              <button
                type="button"
                onClick={() => {
                  setSimMode('range');
                  setValidationError(null);
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all ${
                  simMode === 'range'
                    ? 'bg-[#0A4174] text-white shadow-[0_0_10px_rgba(123,189,232,0.3)] border border-[#7BBDE8]/40'
                    : 'text-[#6EA2B3] hover:text-white'
                }`}
              >
                Port Range Scan
              </button>
            </div>
          </div>

          {simMode === 'range' && (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-[#001D39]/60 border border-[#7BBDE8]/30 rounded-lg">
              <span className="text-xs font-bold text-[#6EA2B3] uppercase tracking-wider">
                Number of Target Ports:
              </span>
              <span
                className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                  targetPortsCount > 11 || targetPortsCount < 1
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                }`}
              >
                {targetPortsCount} {targetPortsCount === 1 ? 'port' : 'ports'}
                {targetPortsCount > 11 && ' (Backend limit is 11)'}
              </span>
            </div>
          )}
        </div>

        {/* Validation Error Alert */}
        {validationError && (
          <div className="mb-6 bg-rose-500/10 border border-rose-500/40 rounded-xl p-3.5 flex items-center gap-3 text-rose-300 text-xs animate-in fade-in">
            <AlertTriangle size={16} className="text-rose-400 flex-shrink-0" />
            <span className="font-medium">{validationError}</span>
          </div>
        )}

        {/* Simulator Configuration */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">

          <div>

            <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
              Protocol
            </label>

            <select
              value={simConfig.protocol}
              onChange={(e) =>
                setSimConfig({
                  ...simConfig,
                  protocol:
                    e.target.value
                })
              }
              className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
            >

              <option value="UDP">
                UDP
              </option>

              <option value="TCP">
                TCP
              </option>

            </select>

          </div>


          <div>

            <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
              Dest IP
            </label>

            <input
              type="text"
              value={simConfig.dest_ip}
              onChange={(e) =>
                setSimConfig({
                  ...simConfig,
                  dest_ip:
                    e.target.value
                })
              }
              className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
            />

          </div>

          {/* Port input(s) based on mode */}
          {simMode === 'single' ? (
            <div>

              <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
                Dest Port
              </label>

              <input
                type="number"
                value={simConfig.dest_port}
                onChange={(e) =>
                  setSimConfig({
                    ...simConfig,
                    dest_port:
                      parseInt(
                        e.target.value
                      ) || 0
                  })
                }
                className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
              />

            </div>
          ) : (
            <>
              <div>

                <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
                  Start Port
                </label>

                <input
                  type="number"
                  value={rangeStart}
                  onChange={(e) =>
                    setRangeStart(parseInt(e.target.value) || 0)
                  }
                  className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
                />

              </div>

              <div>

                <div className="flex justify-between items-center mb-1">
                  <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider">
                    End Port
                  </label>
                  <span className="text-[10px] text-[#7BBDE8] font-mono">
                    {targetPortsCount} ports
                  </span>
                </div>

                <input
                  type="number"
                  value={rangeEnd}
                  onChange={(e) =>
                    setRangeEnd(parseInt(e.target.value) || 0)
                  }
                  className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
                />

              </div>

              <div>

                <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
                  Number of Target Ports
                </label>

                <div className="w-full bg-[#001D39]/40 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white flex items-center justify-between">
                  <span className="font-mono font-bold text-[#7BBDE8]">
                    {targetPortsCount} {targetPortsCount === 1 ? 'Port' : 'Ports'}
                  </span>
                  <span className="text-[10px] text-[#6EA2B3] uppercase">
                    {targetPortsCount > 11 ? 'Exceeds limit' : 'Calculated'}
                  </span>
                </div>

              </div>
            </>
          )}

          <div>

            <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
              Connections
            </label>

            <input
              type="number"
              value={
                simConfig.num_connections
              }
              onChange={(e) =>
                setSimConfig({
                  ...simConfig,
                  num_connections:
                    parseInt(
                      e.target.value
                    )
                })
              }
              className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
            />

          </div>


          <div>

            <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
              Packets / Conn
            </label>

            <input
              type="number"
              value={
                simConfig.packets_per_connection
              }
              onChange={(e) =>
                setSimConfig({
                  ...simConfig,
                  packets_per_connection:
                    parseInt(
                      e.target.value
                    )
                })
              }
              className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
            />

          </div>


          <div>

            <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
              Payload Size (B)
            </label>

            <input
              type="number"
              value={
                simConfig.payload_size
              }
              onChange={(e) =>
                setSimConfig({
                  ...simConfig,
                  payload_size:
                    parseInt(
                      e.target.value
                    )
                })
              }
              className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
            />

          </div>


          <div>

            <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
              Pkt Delay (s)
            </label>

            <input
              type="number"
              step="0.1"
              value={
                simConfig.delay_between_packets
              }
              onChange={(e) =>
                setSimConfig({
                  ...simConfig,
                  delay_between_packets:
                    parseFloat(
                      e.target.value
                    )
                })
              }
              className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
            />

          </div>


          <div>

            <label className="block text-xs font-bold text-[#6EA2B3] uppercase tracking-wider mb-1">
              Conn Delay (s)
            </label>

            <input
              type="number"
              step="0.1"
              value={
                simConfig.delay_between_connections
              }
              onChange={(e) =>
                setSimConfig({
                  ...simConfig,
                  delay_between_connections:
                    parseFloat(
                      e.target.value
                    )
                })
              }
              className="w-full bg-[#001D39]/60 border border-[#49769F]/40 rounded-lg px-3 py-2 text-white"
            />

          </div>

        </div>


        {/* Run Simulation */}
        <div className="flex flex-col md:flex-row gap-6 items-center mb-8">

          <button
            onClick={handleSimulate}
            disabled={
              !isRunning ||
              isSimActive ||
              isSubmitting
            }
            className="w-full md:w-auto bg-[#0A4174]/80 hover:bg-[#49769F]/80 text-white font-bold py-3 px-8 rounded-xl flex items-center justify-center gap-2 transition-all disabled:opacity-50 border border-[#7BBDE8]/30 shadow-[0_0_15px_rgba(123,189,232,0.15)] cursor-pointer disabled:cursor-not-allowed"
          >

            <Play
              size={16}
              className="text-[#7BBDE8]"
              fill="currentColor"
            />

            <span>
              {isSubmitting ? 'STARTING...' : 'RUN SIMULATION'}
            </span>

          </button>


          <div className="flex-1 w-full flex flex-col justify-center bg-[#0A4174]/20 p-3 rounded-lg border border-[#49769F]/30 min-h-[50px]">

            <div className="flex items-center gap-2">

              <span className="text-xs font-bold text-[#6EA2B3] uppercase tracking-wider">
                Status:
              </span>

              <span
                className={`text-sm font-bold ${isSimActive
                    ? 'text-emerald-400 animate-pulse'
                    : isSubmitting
                      ? 'text-[#7BBDE8] animate-pulse'
                      : validationError || apiError
                        ? 'text-rose-400'
                        : 'text-white'
                  }`}
              >
                {
                  validationError
                    ? 'VALIDATION ERROR'
                    : apiError
                      ? 'ERROR'
                      : isSubmitting
                        ? 'STARTING'
                        : isRunning
                          ? simState
                          : 'IDLE'
                }
              </span>

            </div>


            {!isRunning ? (

              <p className="text-xs text-amber-400/80 mt-1">
                Start live capture before running a traffic simulation.
              </p>

            ) : displayMessage ? (

              <p className={`text-xs mt-1 ${validationError ? 'text-rose-300 font-medium' : 'text-[#BDD8E9]'}`}>
                {displayMessage}
              </p>

            ) : null}

          </div>

        </div>


        {/* Current Simulation Telemetry */}
        {showSimStats && (

          <div className="border-t border-[#49769F]/30 pt-6">

            <div className="flex items-center justify-between mb-4">

              <h3 className="text-lg font-bold text-white flex items-center gap-2">

                <Activity
                  size={20}
                  className="text-[#7BBDE8]"
                />

                {(() => {
                  const currentRun = simRunId || status?.run_id;
                  const isSimulationRun = currentRun?.startsWith('SIM-');
                  
                  if (isSimulationRun) {
                    return simState === 'COMPLETED' ? 'LAST COMPLETED SIMULATION' : 'CURRENT SIMULATION';
                  }

                  if (!isRunning && simState === 'COMPLETED') {
                    return 'LAST COMPLETED SIMULATION';
                  }
                  
                  // Real capture - get the interface label
                  const currentInterface = status?.interface;
                  if (currentInterface) {
                    const interfaceObj = interfaces.find(
                      (iface) => iface.name === currentInterface
                    );
                    const interfaceLabel = interfaceObj?.label || currentInterface;
                    return `CURRENT CAPTURE — ${interfaceLabel}`;
                  }
                  
                  return 'CURRENT CAPTURE';
                })()}

              </h3>


              {(simRunId || status?.run_id) && (

                <div className="bg-[#0A4174]/40 border border-[#7BBDE8]/30 px-3 py-1 rounded text-xs font-mono text-[#7BBDE8]">

                  Run ID: {simRunId || status.run_id}

                </div>

              )}

            </div>


            <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">

              {[
                {
                  label: 'Packets Captured',
                  value:
                    displayStats.total_packets,
                  icon: Activity,
                  color:
                    'text-[#7BBDE8]'
                },
                {
                  label: 'Flows Aggregated',
                  value:
                    displayStats.flushed_flows,
                  icon: Cpu,
                  color:
                    'text-[#6EA2B3]'
                },
                {
                  label: 'Model Predictions',
                  value:
                    displayStats.predictions,
                  icon: CheckCircle,
                  color:
                    'text-emerald-400'
                },
                {
                  label: 'Threat Alerts',
                  value:
                    displayStats.alerts,
                  icon: ShieldAlert,
                  color:
                    'text-rose-400'
                },
                {
                  label: 'Inference Errors',
                  value:
                    displayStats.inference_errors,
                  icon: AlertTriangle,
                  color:
                    'text-amber-400'
                }
              ].map((stat, i) => (

                <div
                  key={i}
                  className="glass-card p-5 relative overflow-hidden group bg-[#001D39]/40"
                >

                  <div
                    className={`absolute -right-4 -top-4 w-16 h-16 ${stat.color} opacity-5 blur-xl group-hover:opacity-10 transition-opacity`}
                  />

                  <div className="flex items-center gap-3 mb-3">

                    <div
                      className={`p-2 rounded-lg bg-[#001D39]/50 border border-[#49769F]/30 ${stat.color}`}
                    >
                      <stat.icon size={16} />
                    </div>

                    <span className="text-[10px] font-bold text-[#6EA2B3] uppercase tracking-wider leading-tight">
                      {stat.label}
                    </span>

                  </div>

                  <div className="text-2xl font-black text-white font-mono tracking-tight">
                    {stat.value.toLocaleString()}
                  </div>

                </div>

              ))}

            </div>

          </div>

        )}

      </div>


      {/* =====================================================
          OBSERVED DEVICES
      ===================================================== */}
      <div className="glass-card p-6 mt-6">

        <div className="flex items-center gap-3 mb-6">

          <Smartphone
            size={20}
            className="text-[#7BBDE8]"
          />

          <h2 className="text-xl font-bold text-white">
            OBSERVED DEVICES
          </h2>

        </div>


        {devices.length === 0 ? (

          <p className="text-[#BDD8E9] text-sm py-4">
            No devices observed yet. Devices appear here when traffic is captured and predicted.
          </p>

        ) : (

          <div className="overflow-x-auto">

            <table className="w-full text-left border-collapse">

              <thead>

                <tr className="border-b border-[#49769F]/30">

                  <th className="py-3 px-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider">
                    Device IP
                  </th>

                  <th className="py-3 px-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider">
                    Label
                  </th>

                  <th className="py-3 px-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider text-right">
                    Predictions
                  </th>

                  <th className="py-3 px-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider text-right">
                    Threats
                  </th>

                  <th className="py-3 px-4 text-xs font-bold text-[#6EA2B3] uppercase tracking-wider">
                    Last Seen
                  </th>

                </tr>

              </thead>


              <tbody>

                {devices.map(
                  (dev, idx) => (

                    <tr
                      key={idx}
                      className="border-b border-[#001D39]/30 hover:bg-[#001D39]/20 transition-colors"
                    >

                      <td className="py-4 px-4 font-mono text-sm text-[#BDD8E9]">
                        {dev.ip}
                      </td>

                      <td className="py-4 px-4">

                        <input
                          type="text"
                          value={
                            deviceLabels[
                            dev.ip
                            ] || ''
                          }
                          onChange={(e) =>
                            setDeviceLabels({
                              ...deviceLabels,
                              [dev.ip]:
                                e.target.value
                            })
                          }
                          placeholder="e.g. My Phone"
                          className="bg-[#001D39]/60 border border-[#49769F]/40 rounded px-2 py-1 text-sm text-white focus:outline-none focus:border-[#7BBDE8]"
                        />

                      </td>

                      <td className="py-4 px-4 text-right text-emerald-400 font-bold">
                        {dev.predictions}
                      </td>

                      <td className="py-4 px-4 text-right text-rose-400 font-bold">
                        {
                          dev.threats > 0
                            ? dev.threats
                            : 0
                        }
                      </td>

                      <td className="py-4 px-4 text-sm text-[#BDD8E9]">
                        {
                          new Date(
                            dev.last_seen
                          ).toLocaleTimeString()
                        }
                      </td>

                    </tr>

                  )
                )}

              </tbody>

            </table>

          </div>

        )}

      </div>

    </div>
  );
};

export default LiveMonitor;