'use strict';

/**
 * Biometric Entropy & Behavioral Trajectory Evaluator
 * Evaluates physiological human tremor, kinematic jerk, and keystroke cadence.
 * Copyright (c) 2026 Alexis Grimmace - MIT License
 */

function calculateEntropy(values) {
  if (!Array.isArray(values) || values.length === 0) return 0;
  const counts = new Map();
  for (const v of values) {
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  let entropy = 0;
  const len = values.length;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function evaluatePointerDynamics(rawPoints) {
  // points = [{x, y, t}, ...]
  const points = Array.isArray(rawPoints)
    ? rawPoints
        .filter(
          (p) =>
            p &&
            typeof p === 'object' &&
            Number.isFinite(Number(p.x)) &&
            Number.isFinite(Number(p.y)) &&
            Number.isFinite(Number(p.t))
        )
        .map((p) => ({ x: Number(p.x), y: Number(p.y), t: Number(p.t) }))
    : [];
  if (points.length < 3) {
    return { valid: false, reason: 'insufficient_points', entropy: 0, isLinear: false, isSyntheticJerk: false };
  }

  const angles = [];
  const velocities = [];
  const accelerations = [];
  const jerks = [];
  const dts = [];

  for (let i = 1; i < points.length; i++) {
    const p1 = points[i - 1];
    const p2 = points[i];
    const dx = p2.x - p1.x;
    const dy = p2.y - p1.y;
    const dt = Math.max(1, p2.t - p1.t);
    dts.push(dt);

    const dist = Math.hypot(dx, dy);
    const vel = dist / dt;
    velocities.push(Math.round(vel * 100) / 100);

    const angle = Math.round((Math.atan2(dy, dx) * 180) / Math.PI);
    angles.push(angle);

    if (i >= 2) {
      const prevVel = velocities[i - 2];
      const accel = (vel - prevVel) / dt;
      accelerations.push(accel);

      if (i >= 3) {
        const prevAccel = accelerations[i - 3];
        const jerk = (accel - prevAccel) / dt;
        jerks.push(jerk);
      }
    }
  }

  const angleEntropy = calculateEntropy(angles);
  const velocityEntropy = calculateEntropy(velocities);

  // Perfectly linear movements (bots) have angle entropy close to 0
  const isLinear = angleEntropy < 0.5 && points.length > 5;
  // Constant speeds or instant jumps (> 50px/ms)
  const isInstant = velocities.some((v) => v > 50);

  // 3rd Derivative Kinematic Jerk Evaluation (Physiological hand tremor detection)
  // Human motor control naturally experiences micro-tremors (8-12 Hz) resulting in non-zero jerk variation.
  // Synthetic splines or bot scripts that interpolate points mathematically have zero or constant jerk.
  let isSyntheticJerk = false;
  let jerkEntropy = 0;
  if (jerks.length >= 4) {
    const roundedJerks = jerks.map((j) => Math.round(j * 1000) / 1000);
    jerkEntropy = calculateEntropy(roundedJerks);
    // If there is movement across multiple points but jerk entropy is near zero, it's artificially generated
    if (jerkEntropy < 0.2 && points.length >= 8) {
      isSyntheticJerk = true;
    }
  }

  // Detect synthetic uniform frame-interval generators (e.g. loop with constant dt step across >= 8 samples)
  if (dts.length >= 7) {
    const avgDt = dts.reduce((a, b) => a + b, 0) / dts.length;
    const dtVar = dts.reduce((a, b) => a + Math.pow(b - avgDt, 2), 0) / dts.length;
    if (dtVar === 0 && angleEntropy < 1.2) {
      isSyntheticJerk = true;
    }
  }

  return {
    valid: !isLinear && !isSyntheticJerk,
    angleEntropy,
    velocityEntropy,
    jerkEntropy,
    isLinear,
    isInstant,
    isSyntheticJerk,
    pointCount: points.length,
  };
}

function evaluateKeystrokeCadence(rawIntervals) {
  // intervals = [dt1, dt2, ...] in ms
  const intervals = Array.isArray(rawIntervals)
    ? rawIntervals.map((n) => Number(n)).filter((n) => Number.isFinite(n) && n >= 0)
    : [];
  if (intervals.length < 2) {
    return { valid: true, variance: 1, count: intervals.length, isSyntheticCadence: false };
  }

  const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / intervals.length;

  // Artificial scripts typing with sleep(50ms) have variance < 3ms
  const isSyntheticCadence = variance < 3 && intervals.length >= 4;

  return {
    valid: !isSyntheticCadence,
    averageMs: avg,
    variance,
    count: intervals.length,
    isSyntheticCadence,
  };
}

/**
 * Mobile Touch & Biometric Pressure Dynamics Evaluator
 * Verifies biological finger contact mechanics (pressure ramp and contact area micro-expansion).
 */
function evaluateTouchDynamics(touches) {
  if (!Array.isArray(touches) || touches.length < 3) {
    return { valid: true, count: touches ? touches.length : 0, isSyntheticTouch: false };
  }

  const forces = [];
  const radii = [];
  for (const touch of touches) {
    if (typeof touch.f === 'number') forces.push(touch.f);
    if (typeof touch.r === 'number') radii.push(touch.r);
  }

  // Check pressure variance
  let isSyntheticTouch = false;
  if (forces.length >= 4) {
    const avgForce = forces.reduce((a, b) => a + b, 0) / forces.length;
    const forceVariance = forces.reduce((a, b) => a + Math.pow(b - avgForce, 2), 0) / forces.length;
    // Scripted touch synthesis (force locked at 1.0 or constant)
    if (forceVariance === 0 && forces.length >= 5) {
      isSyntheticTouch = true;
    }
  }

  return {
    valid: !isSyntheticTouch,
    isSyntheticTouch,
    touchCount: touches.length,
  };
}

/**
 * Ephemeral GPU Renderer & Hardware Acceleration Validator
 * Detects headless software rasterizers (SwiftShader, llvmpipe) claiming to be real client hardware.
 */
function evaluateGpuRenderer(rendererString, userAgent = '') {
  if (!rendererString || typeof rendererString !== 'string') {
    return { isSoftwareRasterizer: false };
  }

  const isSoftware = /SwiftShader|llvmpipe|Mesa OffScreen|Software Rasterizer|Microsoft Basic Render Driver|VirtualBox|VMware SVGA/i.test(rendererString);
  const isDesktopOrMobile = /Macintosh|iPhone|iPad|Android|Windows NT/i.test(userAgent);

  return {
    renderer: rendererString,
    isSoftwareRasterizer: isSoftware && isDesktopOrMobile,
  };
}

module.exports = {
  calculateEntropy,
  evaluatePointerDynamics,
  evaluateKeystrokeCadence,
  evaluateTouchDynamics,
  evaluateGpuRenderer,
};
