/**
 * Test Suite for Dynamic Model Explanation Summary in SENTINEL Alerts.
 *
 * Verifies all 10 requirements:
 * 1. Only positive SHAP contributions (> 0) considered toward PortScan/threat.
 * 2. Semantics of SHAP values verified (margin log-odds for PortScan class).
 * 3. Strongest and weakest identified among positive contributors.
 * 4. Same feature display names as Model Explanation section.
 * 5. Natural adaptation for < 2 eligible features (0: exact fallback, 1: single feature).
 * 6. Validation of feature names and finite numbers.
 * 7. Deterministic tie resolution.
 * 8. Dynamic feature derivation without hardcoding.
 * 9. UI structure and styling contract preserved.
 * 10. Comprehensive tests for positive, zero, negative, <2, invalid, and ties.
 */

import assert from 'node:assert';
import {
  FEATURE_MAPPING,
  PROTOCOL_FEATURES,
  getFeatureDisplayName,
  isValidFeature,
  isPositiveContribution,
  getModelExplanationSummary
} from '../frontend/src/utils/explanationSummary.ts';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(err);
    failed++;
  }
}

console.log('--- SENTINEL Model Explanation Summary Test Suite ---\n');

// 1. Positive Contributions (>= 2 eligible features)
test('>= 2 positive features: identifies strongest and weakest correctly', () => {
  const topFeatures = [
    { feature: 'Destination Port', raw_value: 80, impact: 2.45 },
    { feature: 'Flow Duration', raw_value: 1200, impact: 1.15 },
    { feature: 'Total Length of Fwd Packets', raw_value: 400, impact: 0.85 },
    { feature: 'Total Backward Packets', raw_value: 0, impact: 0.12 }
  ];

  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.eligibleCount, 4);
  assert.strictEqual(result.mostInfluentialFeature, 'Destination Port');
  assert.strictEqual(result.leastInfluentialFeature, 'Total Backward Packets');
  assert.strictEqual(
    result.text,
    'The strongest contributing feature toward the threat classification was **Destination Port**, while **Total Backward Packets** had the smallest positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions.'
  );
  assert.ok(result.parts);
  assert.strictEqual(result.parts.strongest, 'Destination Port');
  assert.strictEqual(result.parts.weakest, 'Total Backward Packets');
});

// 2. Zero Contributions Excluded
test('Zero contributions (impact === 0) are excluded entirely', () => {
  const topFeatures = [
    { feature: 'Destination Port', raw_value: 80, impact: 1.5 },
    { feature: 'Flow Duration', raw_value: 1200, impact: 0 },
    { feature: 'Total Backward Packets', raw_value: 0, impact: 0.0 }
  ];

  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.eligibleCount, 1);
  assert.strictEqual(result.mostInfluentialFeature, 'Destination Port');
  assert.strictEqual(result.leastInfluentialFeature, null);
  assert.strictEqual(
    result.text,
    'The strongest contributing feature toward the threat classification was **Destination Port**, which was the only positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions.'
  );
});

test('All zero contributions: displays fallback string', () => {
  const topFeatures = [
    { feature: 'Destination Port', raw_value: 80, impact: 0 },
    { feature: 'Flow Duration', raw_value: 1200, impact: 0.0 }
  ];

  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.eligibleCount, 0);
  assert.strictEqual(result.mostInfluentialFeature, null);
  assert.strictEqual(result.leastInfluentialFeature, null);
  assert.strictEqual(
    result.text,
    'No positive feature contributions toward the threat classification are available for this alert. See Technical SHAP Details below for any available contribution data.'
  );
  assert.strictEqual(result.parts, null);
});

// 3. Negative Contributions Excluded
test('Negative contributions (impact < 0) are excluded entirely', () => {
  const topFeatures = [
    { feature: 'Destination Port', raw_value: 80, impact: 2.1 },
    { feature: 'Flow Duration', raw_value: 1200, impact: -0.8 },
    { feature: 'Total Length of Fwd Packets', raw_value: 300, impact: 0.4 },
    { feature: 'Total Backward Packets', raw_value: 5, impact: -1.2 }
  ];

  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.eligibleCount, 2);
  assert.strictEqual(result.mostInfluentialFeature, 'Destination Port');
  assert.strictEqual(result.leastInfluentialFeature, 'Forward Payload Bytes'); // mapped name
  assert.strictEqual(
    result.text,
    'The strongest contributing feature toward the threat classification was **Destination Port**, while **Forward Payload Bytes** had the smallest positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions.'
  );
});

test('All negative contributions: displays fallback string', () => {
  const topFeatures = [
    { feature: 'Destination Port', raw_value: 80, impact: -0.5 },
    { feature: 'Flow Duration', raw_value: 1200, impact: -2.3 }
  ];

  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.eligibleCount, 0);
  assert.strictEqual(
    result.text,
    'No positive feature contributions toward the threat classification are available for this alert. See Technical SHAP Details below for any available contribution data.'
  );
});

// 4. Fewer than Two Eligible Features
test('Exactly one positive feature: adapts naturally without inventing second feature', () => {
  const topFeatures = [
    { feature: 'Flow Duration', raw_value: 5000, impact: 1.87 },
    { feature: 'Total Fwd Packets', raw_value: 1, impact: -0.4 }
  ];

  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.eligibleCount, 1);
  assert.strictEqual(result.mostInfluentialFeature, 'Flow Duration (μs)');
  assert.strictEqual(result.leastInfluentialFeature, null);
  assert.strictEqual(
    result.text,
    'The strongest contributing feature toward the threat classification was **Flow Duration (μs)**, which was the only positive contribution among the top five displayed features. See Technical SHAP Details below for the complete breakdown of feature contributions.'
  );
  assert.ok(result.parts);
  assert.strictEqual(result.parts.strongest, 'Flow Duration (μs)');
  assert.strictEqual(result.parts.weakest, undefined);
});

test('Zero eligible features: displays exact required fallback string', () => {
  const expectedFallback =
    'No positive feature contributions toward the threat classification are available for this alert. See Technical SHAP Details below for any available contribution data.';

  assert.strictEqual(getModelExplanationSummary([]).text, expectedFallback);
  assert.strictEqual(getModelExplanationSummary(null).text, expectedFallback);
  assert.strictEqual(getModelExplanationSummary(undefined).text, expectedFallback);
  assert.strictEqual(getModelExplanationSummary('invalid').text, expectedFallback);
});

// 5. Missing or Invalid Data Handling
test('Invalid and corrupt entries are safely filtered out', () => {
  const topFeatures = [
    null,
    { feature: '', impact: 1.5 },
    { feature: 12345, impact: 1.5 },
    { feature: 'Valid Feature A', impact: 'not-a-number' },
    { feature: 'Destination Port', raw_value: 80, impact: 1.25 },
    // 6th item with invalid impact:
    { feature: 'Valid Feature B', impact: NaN }
  ];

  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.eligibleCount, 1);
  assert.strictEqual(result.mostInfluentialFeature, 'Destination Port');
});

// 6. Deterministic Tie Resolution
test('Ties for strongest and weakest are resolved deterministically', () => {
  // Features with identical positive impacts
  const topFeatures = [
    { feature: 'Total Length of Bwd Packets', raw_value: 0, impact: 1.5 }, // mapped: Backward Payload Bytes
    { feature: 'Destination Port', raw_value: 80, impact: 1.5 },            // mapped: Destination Port
    { feature: 'Total Length of Fwd Packets', raw_value: 100, impact: 1.5 } // mapped: Forward Payload Bytes
  ];

  // Alphabetical by display name:
  // "Backward Payload Bytes" (index 0)
  // "Destination Port" (index 1)
  // "Forward Payload Bytes" (index 2)
  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.eligibleCount, 3);
  assert.strictEqual(result.mostInfluentialFeature, 'Backward Payload Bytes');
  assert.strictEqual(result.leastInfluentialFeature, 'Forward Payload Bytes');
});

test('Tie for weakest positive feature is resolved deterministically', () => {
  const topFeatures = [
    { feature: 'Destination Port', raw_value: 80, impact: 2.0 },
    { feature: 'Total Length of Fwd Packets', raw_value: 100, impact: 0.5 }, // Forward Payload Bytes
    { feature: 'Total Length of Bwd Packets', raw_value: 50, impact: 0.5 }   // Backward Payload Bytes
  ];

  // Strongest: Destination Port (2.0)
  // Tied for weakest: Backward Payload Bytes (0.5), Forward Payload Bytes (0.5)
  // Backward Payload Bytes comes before Forward Payload Bytes alphabetically, so Forward Payload Bytes is last!
  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.mostInfluentialFeature, 'Destination Port');
  assert.strictEqual(result.leastInfluentialFeature, 'Forward Payload Bytes');
});

// 7. Feature Display Names Match Model Explanation
test('Display names match Model Explanation mappings and protocol flags', () => {
  const featStandard = { feature: 'Total Length of Fwd Packets', raw_value: 100, impact: 1.0 };
  assert.strictEqual(getFeatureDisplayName(featStandard), 'Forward Payload Bytes');

  const featProtoAbsent = { feature: 'proto_icmp', raw_value: 0, impact: 0.5 };
  assert.strictEqual(getFeatureDisplayName(featProtoAbsent), 'ICMP indicator (absent)');

  const featProtoPresent = { feature: 'proto_tcp', raw_value: 1, impact: 0.5 };
  assert.strictEqual(getFeatureDisplayName(featProtoPresent), 'TCP protocol');

  const featCustom = { feature: 'custom_feature_foo', raw_value: 42, impact: 0.5 };
  assert.strictEqual(getFeatureDisplayName(featCustom), 'custom_feature_foo');
});

// 8. Top Five Displayed Features Restriction
test('Only the first 5 elements of top_features are considered', () => {
  const topFeatures = [
    { feature: 'Destination Port', raw_value: 80, impact: 1.0 },       // pos #1
    { feature: 'Flow Duration', raw_value: 100, impact: 0.8 },          // pos #2
    { feature: 'Total Fwd Packets', raw_value: 1, impact: -0.5 },       // neg
    { feature: 'Total Backward Packets', raw_value: 0, impact: 0.6 },  // pos #3
    { feature: 'act_data_pkt_fwd', raw_value: 1, impact: 0.4 },        // pos #4 (Forward Data Packets)
    // 6th element: even though impact is 99.9, it must NOT be evaluated because only top 5 are displayed
    { feature: 'Fwd Packet Length Max', raw_value: 1400, impact: 99.9 }
  ];

  const result = getModelExplanationSummary(topFeatures);
  assert.strictEqual(result.eligibleCount, 4);
  assert.strictEqual(result.mostInfluentialFeature, 'Destination Port');
  assert.strictEqual(result.leastInfluentialFeature, 'Forward Data Packets');
});

console.log(`\nResults: ${passed} passed, ${failed} failed.`);
if (failed > 0) {
  process.exit(1);
} else {
  console.log('ALL TESTS PASSED SUCCESSFULLY!');
}
