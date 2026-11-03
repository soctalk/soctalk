import { describe, expect, it } from 'vitest';
import { loginPath, safeNextPath } from './session-expiry';

describe('safeNextPath', () => {
	it('keeps same-origin app paths with their query and hash', () => {
		expect(safeNextPath('/investigations')).toBe('/investigations');
		expect(safeNextPath('/investigations?status=pending#top')).toBe(
			'/investigations?status=pending#top'
		);
		expect(safeNextPath('/')).toBe('/');
	});

	it('drops the locale prefix so the login page can re-apply its own', () => {
		expect(safeNextPath('/pt-br/investigations')).toBe('/investigations');
		expect(safeNextPath('/de-de')).toBe('/');
	});

	it('rejects anything that leaves the origin', () => {
		for (const raw of [
			'https://evil.example',
			'http://evil.example/investigations',
			'//evil.example',
			'//evil.example/investigations',
			'/\\evil.example',
			'/\t/evil.example',
			'/\n/evil.example',
			'javascript:alert(1)',
			'data:text/html,hi',
			'evil.example',
			'investigations',
			'',
			' /investigations'
		]) {
			expect(safeNextPath(raw), raw).toBeNull();
		}
	});

	it('rejects the login page itself, with or without a locale', () => {
		expect(safeNextPath('/login')).toBeNull();
		expect(safeNextPath('/login?expired=1')).toBeNull();
		expect(safeNextPath('/fr-fr/login')).toBeNull();
	});

	it('rejects missing values', () => {
		expect(safeNextPath(null)).toBeNull();
		expect(safeNextPath(undefined)).toBeNull();
	});
});

describe('loginPath', () => {
	it('is plain /login without options', () => {
		expect(loginPath()).toBe('/login');
	});

	it('marks an expiry and encodes the return path', () => {
		expect(loginPath({ expired: true, next: '/investigations?status=pending' })).toBe(
			'/login?expired=1&next=%2Finvestigations%3Fstatus%3Dpending'
		);
	});

	it('marks a sign-out', () => {
		expect(loginPath({ signedOut: true })).toBe('/login?signed_out=1');
	});

	it('omits a next that is the landing route or unsafe', () => {
		expect(loginPath({ next: '/' })).toBe('/login');
		expect(loginPath({ next: '//evil.example' })).toBe('/login');
		expect(loginPath({ expired: true, next: '/login' })).toBe('/login?expired=1');
	});
});
