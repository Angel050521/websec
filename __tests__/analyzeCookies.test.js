'use strict';

const { analyzeCookies } = require('../app.testable');

describe('analyzeCookies', () => {

    // ── No cookies ──
    test('retorna array vacío si no hay set-cookie', () => {
        expect(analyzeCookies({})).toEqual([]);
        expect(analyzeCookies({ 'content-type': 'text/html' })).toEqual([]);
    });

    test('retorna array vacío si set-cookie está vacío', () => {
        expect(analyzeCookies({ 'set-cookie': '' })).toEqual([]);
    });

    // ── HttpOnly ──
    describe('Flag HttpOnly', () => {
        test('detecta cookie sin HttpOnly', () => {
            const findings = analyzeCookies({
                'set-cookie': 'session=abc123; Path=/; Secure; SameSite=Lax'
            });
            const f = findings.find(f => f.title.includes('HttpOnly'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('M');
        });

        test('no reporta si HttpOnly está presente', () => {
            const findings = analyzeCookies({
                'set-cookie': 'session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax'
            });
            const f = findings.find(f => f.title.includes('HttpOnly'));
            expect(f).toBeUndefined();
        });
    });

    // ── Secure ──
    describe('Flag Secure', () => {
        test('detecta cookie sin Secure', () => {
            const findings = analyzeCookies({
                'set-cookie': 'session=abc123; Path=/; HttpOnly; SameSite=Lax'
            });
            const f = findings.find(f => f.title.includes('Secure'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('M');
        });

        test('no reporta si Secure está presente', () => {
            const findings = analyzeCookies({
                'set-cookie': 'session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax'
            });
            const f = findings.find(f => f.title.includes('sin flag Secure'));
            expect(f).toBeUndefined();
        });
    });

    // ── SameSite ──
    describe('Flag SameSite', () => {
        test('detecta cookie sin SameSite', () => {
            const findings = analyzeCookies({
                'set-cookie': 'session=abc123; Path=/; HttpOnly; Secure'
            });
            const f = findings.find(f => f.title.includes('SameSite'));
            expect(f).toBeDefined();
            expect(f.sev).toBe('L');
        });

        test('no reporta si SameSite está presente', () => {
            const findings = analyzeCookies({
                'set-cookie': 'session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict'
            });
            const f = findings.find(f => f.title.includes('SameSite'));
            expect(f).toBeUndefined();
        });
    });

    // ── Cookie perfecta ──
    test('no reporta ningún problema con cookie completamente segura', () => {
        const findings = analyzeCookies({
            'set-cookie': 'session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict'
        });
        expect(findings).toHaveLength(0);
    });

    // ── Cookie totalmente insegura ──
    test('reporta 3 problemas para cookie sin ningún flag', () => {
        const findings = analyzeCookies({
            'set-cookie': 'session=abc123; Path=/'
        });
        // Should find: no HttpOnly, no Secure, no SameSite
        expect(findings.length).toBe(3);
    });

    // ── Múltiples cookies ──
    test('analiza múltiples cookies separadas por coma', () => {
        const findings = analyzeCookies({
            'set-cookie': 'a=1; Path=/, b=2; Path=/; HttpOnly'
        });
        // Cookie "a": missing HttpOnly, Secure, SameSite = 3 findings
        // Cookie "b": missing Secure, SameSite = 2 findings
        expect(findings.length).toBe(5);
    });

    // ── Cookie name extraction ──
    test('incluye el nombre de la cookie en el título', () => {
        const findings = analyzeCookies({
            'set-cookie': 'PHPSESSID=abc123; Path=/'
        });
        const f = findings.find(f => f.title.includes('PHPSESSID'));
        expect(f).toBeDefined();
    });
});
