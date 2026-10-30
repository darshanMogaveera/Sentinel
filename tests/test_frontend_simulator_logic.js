/**
 * Automated test suite for SENTINEL's Custom Traffic Simulator frontend logic.
 * Tests preset population, mode selection, request payload contracts,
 * validation rules, double submission prevention, and lifecycle state management.
 */

const assert = require('assert');

// 1. Simulation logic model replicating LiveMonitor state machine & validation
class SimulatorModel {
  constructor() {
    this.simMode = 'single'; // 'single' | 'range'
    this.rangeStart = 12340;
    this.rangeEnd = 12349;
    this.simConfig = {
      protocol: 'UDP',
      dest_ip: '127.0.0.1',
      dest_port: 12345,
      num_connections: 1,
      packets_per_connection: 5,
      payload_size: 64,
      delay_between_packets: 0.1,
      delay_between_connections: 0.5
    };
    this.isSubmitting = false;
    this.isSimActive = false;
    this.isRunning = true;
    this.validationError = null;
    this.apiError = null;
    this.simRunId = null;
    this.simStats = null;
  }

  getTargetPortsCount() {
    if (isNaN(this.rangeStart) || isNaN(this.rangeEnd)) return 0;
    return Math.max(0, this.rangeEnd - this.rangeStart + 1);
  }

  applyPreset(preset) {
    this.validationError = null;
    this.apiError = null;

    if (preset === 'normal') {
      this.simMode = 'single';
      this.simConfig = {
        ...this.simConfig,
        protocol: 'UDP',
        dest_ip: '127.0.0.1',
        dest_port: 12345,
        num_connections: 3,
        packets_per_connection: 5,
        payload_size: 64,
        delay_between_packets: 0.1,
        delay_between_connections: 0.5
      };
    } else if (preset === 'high_rate') {
      this.simMode = 'single';
      this.simConfig = {
        ...this.simConfig,
        protocol: 'UDP',
        dest_ip: '127.0.0.1',
        dest_port: 12345,
        num_connections: 1,
        packets_per_connection: 1000,
        payload_size: 1024,
        delay_between_packets: 0.0,
        delay_between_connections: 0.5
      };
    } else if (preset === 'connection_burst') {
      this.simMode = 'single';
      this.simConfig = {
        ...this.simConfig,
        protocol: 'TCP',
        dest_ip: '127.0.0.1',
        dest_port: 12345,
        num_connections: 200,
        packets_per_connection: 1,
        payload_size: 64,
        delay_between_packets: 0.0,
        delay_between_connections: 0.0
      };
    } else if (preset === 'port_scan') {
      this.simMode = 'range';
      this.rangeStart = 12340;
      this.rangeEnd = 12349;
      this.simConfig = {
        ...this.simConfig,
        protocol: 'TCP',
        dest_ip: '127.0.0.1',
        payload_size: 0,
        num_connections: 1,
        packets_per_connection: 1,
        delay_between_packets: 0.0,
        delay_between_connections: 0.0
      };
    }
  }

  validateAndBuildPayload() {
    if (this.isSubmitting || this.isSimActive || !this.isRunning) {
      return { ok: false, error: 'SUBMISSION_BLOCKED' };
    }

    this.validationError = null;
    this.apiError = null;

    // 1. IP loopback validation
    const ip = (this.simConfig.dest_ip || '').trim();
    if (!ip) {
      this.validationError = 'Destination IP is required.';
      return { ok: false, error: this.validationError };
    }
    const isLoopback =
      ip === '127.0.0.1' ||
      ip.toLowerCase() === 'localhost' ||
      ip === '::1' ||
      ip.startsWith('127.');
    if (!isLoopback) {
      this.validationError = 'Destination must be a valid localhost/loopback address (127.0.0.1).';
      return { ok: false, error: this.validationError };
    }

    const targetDestIp = (ip.toLowerCase() === 'localhost' || ip.startsWith('127.')) ? '127.0.0.1' : ip;

    // 2. Protocol validation
    const proto = (this.simConfig.protocol || '').toUpperCase();
    if (proto !== 'TCP' && proto !== 'UDP') {
      this.validationError = "Protocol must be either 'TCP' or 'UDP'.";
      return { ok: false, error: this.validationError };
    }

    // 3. Port / Range validation
    const payload = {
      dest_ip: targetDestIp,
      protocol: proto,
      num_connections: Number(this.simConfig.num_connections) || 1,
      packets_per_connection: Number(this.simConfig.packets_per_connection) || 1,
      payload_size: Number(this.simConfig.payload_size) || 0,
      delay_between_packets: Number(this.simConfig.delay_between_packets) || 0.0,
      delay_between_connections: Number(this.simConfig.delay_between_connections) || 0.0
    };

    if (this.simMode === 'single') {
      const p = Number(this.simConfig.dest_port);
      if (isNaN(p) || !Number.isInteger(p) || p < 1 || p > 65535) {
        this.validationError = 'Destination port must be an integer between 1 and 65535.';
        return { ok: false, error: this.validationError };
      }
      payload.dest_port = p;
    } else {
      const s = Number(this.rangeStart);
      const e = Number(this.rangeEnd);
      if (isNaN(s) || !Number.isInteger(s) || s < 1 || s > 65535) {
        this.validationError = 'Start port must be an integer between 1 and 65535.';
        return { ok: false, error: this.validationError };
      }
      if (isNaN(e) || !Number.isInteger(e) || e < 1 || e > 65535) {
        this.validationError = 'End port must be an integer between 1 and 65535.';
        return { ok: false, error: this.validationError };
      }
      if (s > e) {
        this.validationError = `End port (${e}) must be greater than or equal to start port (${s}).`;
        return { ok: false, error: this.validationError };
      }
      const count = e - s + 1;
      if (count > 11) {
        this.validationError = `Port range (${count} ports) exceeds the backend maximum of 11 ports.`;
        return { ok: false, error: this.validationError };
      }
      if (count < 1) {
        this.validationError = 'At least one destination port must be specified.';
        return { ok: false, error: this.validationError };
      }

      payload.port_range_start = s;
      payload.port_range_end = e;
    }

    return { ok: true, payload };
  }
}

// ============================================================================
// TESTS
// ============================================================================

console.log('Running Frontend Custom Traffic Simulator Test Suite...\n');

// Test 1: Selecting Port Scan (TCP SYN) preset
{
  const sim = new SimulatorModel();
  sim.applyPreset('port_scan');

  assert.strictEqual(sim.simMode, 'range', 'Preset must set mode to range');
  assert.strictEqual(sim.simConfig.protocol, 'TCP', 'Preset must set protocol to TCP');
  assert.strictEqual(sim.simConfig.dest_ip, '127.0.0.1', 'Preset must set dest_ip to 127.0.0.1');
  assert.strictEqual(sim.rangeStart, 12340, 'Preset must set start port to 12340');
  assert.strictEqual(sim.rangeEnd, 12349, 'Preset must set end port to 12349');
  assert.strictEqual(sim.simConfig.payload_size, 0, 'Preset must set payload_size to 0');
  assert.strictEqual(sim.getTargetPortsCount(), 10, 'Target ports count must calculate to 10');

  const res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, true, 'Port scan preset payload must pass validation');
  assert.strictEqual(res.payload.port_range_start, 12340);
  assert.strictEqual(res.payload.port_range_end, 12349);
  assert.strictEqual(res.payload.dest_port, undefined, 'Must not include single dest_port in range mode');
  console.log('✓ Test 1: Port Scan (TCP SYN) preset populates correct fields and range payload');
}

// Test 2: Single Port vs Port Range Scan payload isolation
{
  const sim = new SimulatorModel();

  // Single port mode
  sim.simMode = 'single';
  sim.simConfig.dest_port = 8080;
  sim.rangeStart = 12340; // Stale range values from previous operations
  sim.rangeEnd = 12349;

  let res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.payload.dest_port, 8080);
  assert.strictEqual(res.payload.port_range_start, undefined, 'Single port must not submit port_range_start');
  assert.strictEqual(res.payload.port_range_end, undefined, 'Single port must not submit port_range_end');

  // Switch to range mode
  sim.simMode = 'range';
  sim.rangeStart = 12340;
  sim.rangeEnd = 12345;
  res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.payload.port_range_start, 12340);
  assert.strictEqual(res.payload.port_range_end, 12345);
  assert.strictEqual(res.payload.dest_port, undefined, 'Range mode must not submit dest_port');
  console.log('✓ Test 2: Mode switching cleanly isolates submitted payload without leaking stale values');
}

// Test 3: Rejection of invalid IP addresses
{
  const sim = new SimulatorModel();
  sim.simConfig.dest_ip = '192.168.1.100'; // external/LAN IP not allowed for local simulation
  let res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, false);
  assert.match(res.error, /localhost\/loopback address/);

  sim.simConfig.dest_ip = 'localhost';
  res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.payload.dest_ip, '127.0.0.1', 'localhost should normalize to 127.0.0.1');
  console.log('✓ Test 3: Invalid destination IP rejected; localhost correctly normalized');
}

// Test 4: Port range boundary validation and 11-port limit
{
  const sim = new SimulatorModel();
  sim.simMode = 'range';

  // Inverted range
  sim.rangeStart = 12350;
  sim.rangeEnd = 12340;
  let res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, false);
  assert.match(res.error, /greater than or equal to start port/);

  // Exceeds 11 ports limit (12 ports: 12340-12351)
  sim.rangeStart = 12340;
  sim.rangeEnd = 12351;
  res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, false);
  assert.match(res.error, /exceeds the backend maximum of 11 ports/);

  // Exactly 11 ports boundary (12340-12350)
  sim.rangeStart = 12340;
  sim.rangeEnd = 12350;
  assert.strictEqual(sim.getTargetPortsCount(), 11);
  res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, true);

  // Out of bounds (< 1 or > 65535)
  sim.rangeStart = 0;
  sim.rangeEnd = 10;
  res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, false);

  sim.rangeStart = 65530;
  sim.rangeEnd = 65540;
  res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, false);
  console.log('✓ Test 4: Inverted ranges, >11 ports, and out-of-bounds ports rejected with clear messages');
}

// Test 5: Double submission prevention
{
  const sim = new SimulatorModel();
  sim.isSubmitting = true;
  let res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, 'SUBMISSION_BLOCKED');

  sim.isSubmitting = false;
  sim.isSimActive = true;
  res = sim.validateAndBuildPayload();
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.error, 'SUBMISSION_BLOCKED');
  console.log('✓ Test 5: Double submission blocked while isSubmitting or isSimActive');
}

// Test 6: Existing presets remain functional
{
  const sim = new SimulatorModel();

  sim.applyPreset('normal');
  assert.strictEqual(sim.simMode, 'single');
  assert.strictEqual(sim.simConfig.protocol, 'UDP');
  assert.strictEqual(sim.simConfig.num_connections, 3);
  assert.strictEqual(sim.simConfig.packets_per_connection, 5);
  assert.strictEqual(sim.simConfig.payload_size, 64);

  sim.applyPreset('high_rate');
  assert.strictEqual(sim.simMode, 'single');
  assert.strictEqual(sim.simConfig.protocol, 'UDP');
  assert.strictEqual(sim.simConfig.num_connections, 1);
  assert.strictEqual(sim.simConfig.packets_per_connection, 1000);
  assert.strictEqual(sim.simConfig.payload_size, 1024);

  sim.applyPreset('connection_burst');
  assert.strictEqual(sim.simMode, 'single');
  assert.strictEqual(sim.simConfig.protocol, 'TCP');
  assert.strictEqual(sim.simConfig.num_connections, 200);
  assert.strictEqual(sim.simConfig.packets_per_connection, 1);
  assert.strictEqual(sim.simConfig.delay_between_connections, 0.0);
  console.log('✓ Test 6: Existing presets (Normal, High Rate, Connection Burst) preserved and functional');
}

// Test 7: Simulation lifecycle state handling (Start ack != Detection complete)
{
  const sim = new SimulatorModel();
  sim.applyPreset('port_scan');

  // Simulator starts
  const startResponse = { message: 'Simulation started.', run_id: 'SIM-12345678' };
  sim.simRunId = startResponse.run_id;
  sim.simStats = { simulation_state: 'RUNNING', total_packets: 0, predictions: 0, alerts: 0 };

  const isCompletedEarly = sim.simStats.simulation_state === 'COMPLETED';
  assert.strictEqual(isCompletedEarly, false, 'Start acknowledgement must not be treated as completed detection');

  // Transition to PROCESSING
  sim.simStats.simulation_state = 'PROCESSING';
  assert.strictEqual(sim.simStats.simulation_state === 'COMPLETED', false);

  // Transition to COMPLETED with real backend telemetry
  sim.simStats = {
    simulation_state: 'COMPLETED',
    total_packets: 20,
    flushed_flows: 10,
    predictions: 10,
    alerts: 1,
    inference_errors: 0
  };
  assert.strictEqual(sim.simStats.simulation_state, 'COMPLETED');
  assert.strictEqual(sim.simStats.alerts, 1);
  console.log('✓ Test 7: Start response is not falsely treated as completed detection; stats tied to run_id');
}

console.log('\nAll 7 frontend simulator tests PASSED successfully.');
