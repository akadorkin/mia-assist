import { ScenarioDef } from '../core/scenario.js';
import { fleetUpdate } from './fleet-update.js';
import { xrayRules } from './xray-rules.js';

export const SCENARIOS = new Map<string, ScenarioDef>([xrayRules, fleetUpdate].map((s) => [s.name, s]));
