// Which experimental features this build has, and their exports.
//
// The default build has none. `npm run build:experimental` builds the addon
// with every experimental feature and writes `experimental.js`, which
// re-exports them. With `AITP_EXPECT_EXPERIMENTAL=1` a missing feature fails
// the importing test file instead of skipping its tests.

import * as aitp from '../experimental.js';

const EXPECT = process.env.AITP_EXPECT_EXPERIMENTAL === '1';

function present(ok, feature) {
  if (EXPECT && !ok) {
    throw new Error(`AITP_EXPECT_EXPERIMENTAL=1 but this build lacks ${feature}`);
  }
  return ok;
}

export const {
  SessionBundleBuilder,
  verifySessionBundle,
  verifyDelegationMultihop,
  a2aCardManifestUrl,
  verifyA2aAgentCardBinding,
} = aitp;

export const HAS_RENEWAL = present(
  typeof aitp.AitpAgent.prototype.buildRenewalRequest === 'function',
  'experimental-renewal',
);
export const HAS_BUNDLE = present(
  typeof SessionBundleBuilder === 'function',
  'experimental-session-bundle',
);
export const HAS_MULTIHOP = present(
  typeof verifyDelegationMultihop === 'function',
  'experimental-multihop-delegation',
);
export const HAS_A2A = present(
  typeof verifyA2aAgentCardBinding === 'function',
  'experimental-a2a-agent-card',
);
