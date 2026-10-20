import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPersonalDevice } from '../src/core/panel.js';

test('personal devices are never fleet hosts', () => {
    for (const os of ['macOS', 'iOS', 'iPadOS', 'tvOS', 'android', 'windows', ' macOS ']) assert.equal(isPersonalDevice({ os }), true, os);
    for (const os of ['linux', 'freebsd', '', undefined]) assert.equal(isPersonalDevice({ os }), false, String(os));
});
