
'use strict';

const { detectTech } = require('../app.testable');

describe('detectTech', () => {

    // ── Frontend Frameworks ──
    describe('Frameworks frontend', () => {
        test('detecta Nuxt.js por __nuxt', () => {
            const techs = detectTech('<div id="__nuxt">App</div>', {});
            expect(techs).toContain('Nuxt.js');
        });

        test('detecta Nuxt.js por /_nuxt/ path', () => {
            const techs = detectTech('<script src="/_nuxt/entry.js"></script>', {});
            expect(techs).toContain('Nuxt.js');
        });

        test('detecta Next.js por __next', () => {
            const techs = detectTech('<div id="__next">App</div>', {});
            expect(techs).toContain('Next.js');
        });

        test('detecta Next.js por /_next/ path', () => {
            const techs = detectTech('<script src="/_next/static/chunks/main.js"></script>', {});
            expect(techs).toContain('Next.js');
        });

        test('detecta React por data-reactroot', () => {
            const techs = detectTech('<div data-reactroot="">App</div>', {});
            expect(techs).toContain('React');
        });

        test('detecta Vue.js por data-v-', () => {
            const techs = detectTech('<div data-v-abc123>Component</div>', {});
            expect(techs).toContain('Vue.js');
        });

        test('detecta Angular por ng-version', () => {
            const techs = detectTech('<app ng-version="16.0.0">App</app>', {});
            expect(techs).toContain('Angular');
        });

        test('detecta Svelte por __svelte', () => {
            const techs = detectTech('<div class="__svelte-xyz">App</div>', {});
            expect(techs).toContain('Svelte');
        });

        test('detecta Astro por astro-', () => {
            const techs = detectTech('<div class="astro-abc123">Page</div>', {});
            expect(techs).toContain('Astro');
        });

        test('detecta Remix por remix-', () => {
            const techs = detectTech('<script data-remix-run="true"></script>', {});
            expect(techs).toContain('Remix');
        });
    });

    // ── CMS ──
    describe('CMS', () => {
        test('detecta WordPress por wp-content', () => {
            const techs = detectTech('<link rel="stylesheet" href="/wp-content/themes/style.css">', {});
            expect(techs).toContain('WordPress');
        });

        test('detecta WordPress por wp-json', () => {
            const techs = detectTech('<link rel="alternate" href="/wp-json/" >', {});
            expect(techs).toContain('WordPress');
        });

        test('detecta Shopify por cdn.shopify', () => {
            const techs = detectTech('<script src="https://cdn.shopify.com/s/files/1/shop.js"></script>', {});
            expect(techs).toContain('Shopify');
        });
    });

    // ── Backend Frameworks ──
    describe('Backend frameworks', () => {
        test('detecta Laravel por csrf-token', () => {
            const techs = detectTech('<meta name="csrf-token" content="abc123">', {});
            expect(techs).toContain('Laravel');
        });

        test('detecta Django por csrfmiddlewaretoken', () => {
            const techs = detectTech('<input type="hidden" name="csrfmiddlewaretoken" value="token123">', {});
            expect(techs).toContain('Django');
        });
    });

    // ── CSS Frameworks ──
    describe('CSS Frameworks', () => {
        test('detecta Bootstrap', () => {
            const techs = detectTech('<link rel="stylesheet" href="bootstrap.min.css">', {});
            expect(techs).toContain('Bootstrap');
        });

        test('detecta Tailwind CSS', () => {
            const techs = detectTech('<link rel="stylesheet" href="tailwindcss.min.css">', {});
            expect(techs).toContain('Tailwind CSS');
        });
    });

    // ── Libraries ──
    describe('Librerías', () => {
        test('detecta jQuery', () => {
            const techs = detectTech('<script src="jquery.min.js"></script>', {});
            expect(techs).toContain('jQuery');
        });
    });

    // ── Analytics & Services ──
    describe('Analytics y servicios', () => {
        test('detecta Google Analytics por gtag', () => {
            const techs = detectTech('<script>gtag("config", "GA-123");</script>', {});
            expect(techs).toContain('Google Analytics');
        });

        test('detecta MS Clarity', () => {
            const techs = detectTech('<script src="https://www.clarity.ms/tag/xyz"></script>', {});
            expect(techs).toContain('MS Clarity');
        });

        test('detecta Stripe', () => {
            const techs = detectTech('<script src="https://js.stripe.com/v3/"></script>', {});
            expect(techs).toContain('Stripe');
        });

        test('detecta reCAPTCHA', () => {
            const techs = detectTech('<script src="https://www.google.com/recaptcha/api.js"></script>', {});
            expect(techs).toContain('reCAPTCHA');
        });

        test('detecta Hotjar', () => {
            const techs = detectTech('<script>window.hj=window.hj||function(){(hj.q=hj.q||[]).push(arguments)};window._hjSettings={hjid:123};var a=document.getElementsByTagName("head")[0];var r=document.createElement("script");r.async=1;r.src="https://static.hotjar.com/c/hotjar.js";</script>', {});
            expect(techs).toContain('Hotjar');
        });
    });

    // ── Server Detection via Headers ──
    describe('Detección por headers', () => {
        test('detecta PHP por x-powered-by', () => {
            const techs = detectTech('', { 'x-powered-by': 'PHP/8.2' });
            expect(techs).toContain('PHP');
        });

        test('detecta Express.js por x-powered-by', () => {
            const techs = detectTech('', { 'x-powered-by': 'Express' });
            expect(techs).toContain('Express.js');
        });

        test('detecta ASP.NET por x-powered-by', () => {
            const techs = detectTech('', { 'x-powered-by': 'ASP.NET' });
            expect(techs).toContain('ASP.NET');
        });

        test('detecta Nginx por server header', () => {
            const techs = detectTech('', { 'server': 'nginx/1.24.0' });
            expect(techs).toContain('Nginx');
        });

        test('detecta Apache por server header', () => {
            const techs = detectTech('', { 'server': 'Apache/2.4.54' });
            expect(techs).toContain('Apache');
        });

        test('detecta IIS por server header', () => {
            const techs = detectTech('', { 'server': 'Microsoft-IIS/10.0' });
            expect(techs).toContain('IIS');
        });

        test('detecta LiteSpeed por server header', () => {
            const techs = detectTech('', { 'server': 'LiteSpeed' });
            expect(techs).toContain('LiteSpeed');
        });

        test('detecta Vercel por x-vercel-id header', () => {
            const techs = detectTech('', { 'x-vercel-id': 'iad1::12345' });
            expect(techs).toContain('Vercel');
        });

        test('detecta Netlify por x-netlify-request-id', () => {
            const techs = detectTech('', { 'x-netlify-request-id': '12345' });
            expect(techs).toContain('Netlify');
        });

        test('detecta GitHub Pages por server header', () => {
            const techs = detectTech('', { 'server': 'GitHub.com' });
            expect(techs).toContain('GitHub Pages');
        });
    });

    // ── Edge Cases ──
    describe('Edge cases', () => {
        test('no duplica tecnologías', () => {
            const techs = detectTech(
                '<link rel="stylesheet" href="bootstrap.min.css"><script src="bootstrap.bundle.js"></script>',
                {}
            );
            const bootstrapCount = techs.filter(t => t === 'Bootstrap').length;
            expect(bootstrapCount).toBe(1);
        });

        test('detecta múltiples tecnologías simultaneamente', () => {
            const html = '<div id="__next"><script src="jquery.min.js"></script><script>gtag("config")</script></div>';
            const techs = detectTech(html, { 'server': 'nginx/1.24' });
            expect(techs).toContain('Next.js');
            expect(techs).toContain('jQuery');
            expect(techs).toContain('Google Analytics');
            expect(techs).toContain('Nginx');
        });

        test('retorna array vacío para HTML sin tecnologías reconocibles', () => {
            const techs = detectTech('<html><body>Hello</body></html>', {});
            expect(techs).toEqual([]);
        });

        test('maneja headers vacíos correctamente', () => {
            expect(() => detectTech('<html></html>', {})).not.toThrow();
        });
    });
});
