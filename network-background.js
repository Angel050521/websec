class NetworkBackground {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;

        this.ctx = this.canvas.getContext('2d');
        this.particles = [];
        this.mouse = { x: null, y: null, radius: 150 };
        this.animationId = null;
        this.isRunning = false;

        // Device pixel ratio para pantallas HD/Retina
        this.dpr = Math.min(window.devicePixelRatio || 1, 2);

        // Cachear dimensiones de ventana para evitar forced reflow
        this.cachedWindowWidth = window.innerWidth;
        this.cachedWindowHeight = window.innerHeight;

        // Detectar si es móvil
        this.isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) || this.cachedWindowWidth < 768;

        // Escala base para ajustar tamaños según pantalla
        this.scale = Math.min(this.cachedWindowWidth, this.cachedWindowHeight) / 1000;

        // Configuración adaptativa
        this.config = {
            particleCount: this.isMobile ? 40 : 80,
            particleSize: {
                min: this.isMobile ? 1.5 : 1,
                max: this.isMobile ? 4 : 3
            },
            particleSpeed: this.isMobile ? 0.2 : 0.3,
            connectionDistance: this.isMobile ? 100 : 150,
            mouseConnectionDistance: this.isMobile ? 120 : 200,
            // Colores estilo Watch Dogs
            colors: {
                particle: 'rgba(255, 255, 255, 0.8)',
                particleGlow: 'rgba(255, 255, 255, 0.3)',
                line: 'rgba(255, 255, 255, 0.15)',
                lineActive: 'rgba(100, 200, 255, 0.4)',
                nodeHighlight: 'rgba(0, 255, 200, 0.8)',
                nodeSquare: 'rgba(255, 255, 255, 0.6)'
            },
            // Grosor de líneas ajustado para HD
            lineWidth: this.dpr * 0.5,
            lineWidthActive: this.dpr * 1
        };

        this.init();
    }

    init() {
        this.resize();
        this.createParticles();
        this.bindEvents();
        this.start();
    }

    resize() {
        // Actualizar caché de dimensiones de ventana
        this.cachedWindowWidth = window.innerWidth;
        this.cachedWindowHeight = window.innerHeight;

        // Obtener dimensiones CSS
        const rect = this.canvas.getBoundingClientRect();
        const width = rect.width || this.cachedWindowWidth;
        const height = rect.height || this.cachedWindowHeight;

        // Actualizar DPR
        this.dpr = Math.min(window.devicePixelRatio || 1, 2);

        // Establecer dimensiones del canvas en píxeles reales para HD
        this.canvas.width = width * this.dpr;
        this.canvas.height = height * this.dpr;

        // Mantener tamaño visual con CSS
        this.canvas.style.width = width + 'px';
        this.canvas.style.height = height + 'px';

        // Escalar el contexto para que las coordenadas coincidan
        this.ctx.scale(this.dpr, this.dpr);

        // Guardar dimensiones lógicas (las que usamos para cálculos)
        this.width = width;
        this.height = height;

        // Actualizar escala
        this.scale = Math.min(width, height) / 1000;

        // Detectar móvil después de resize
        this.isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) || this.cachedWindowWidth < 768;
    }

    bindEvents() {
        let resizeTimeout;
        window.addEventListener('resize', () => {
            // Debounce para evitar múltiples redraws
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                this.resize();
                this.particles = [];
                this.createParticles();
            }, 100);
        });

        // Soporte para mouse
        window.addEventListener('mousemove', (e) => {
            this.mouse.x = e.clientX;
            this.mouse.y = e.clientY;
        });

        window.addEventListener('mouseout', () => {
            this.mouse.x = null;
            this.mouse.y = null;
        });

        // Soporte para touch - DESACTIVADO en móviles para evitar el punto azul al deslizar
        // Solo se activa en tablets grandes o escritorios con pantalla táctil
        if (!this.isMobile) {
            window.addEventListener('touchmove', (e) => {
                if (e.touches.length > 0) {
                    this.mouse.x = e.touches[0].clientX;
                    this.mouse.y = e.touches[0].clientY;
                }
            }, { passive: true });

            window.addEventListener('touchend', () => {
                this.mouse.x = null;
                this.mouse.y = null;
            }, { passive: true });
        }
    }

    createParticles() {
        // Usar dimensiones lógicas
        const width = this.width || window.innerWidth;
        const height = this.height || window.innerHeight;

        // Ajustar densidad de partículas según área de pantalla
        const area = width * height;
        const baseDensity = this.isMobile ? 25000 : 15000;
        const count = Math.floor(area / baseDensity);
        const particleCount = Math.min(Math.max(count, this.isMobile ? 25 : 40), this.config.particleCount);

        for (let i = 0; i < particleCount; i++) {
            this.particles.push(new Particle(this));
        }

        // Añadir algunos nodos cuadrados (estilo Watch Dogs) - menos en móvil
        const squareCount = this.isMobile ? 4 : 8;
        for (let i = 0; i < squareCount; i++) {
            this.particles.push(new SquareNode(this));
        }
    }

    drawConnections() {
        for (let i = 0; i < this.particles.length; i++) {
            for (let j = i + 1; j < this.particles.length; j++) {
                const dx = this.particles[i].x - this.particles[j].x;
                const dy = this.particles[i].y - this.particles[j].y;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < this.config.connectionDistance) {
                    const opacity = 1 - (distance / this.config.connectionDistance);

                    // Verificar si el mouse está cerca de la línea
                    let lineColor = this.config.colors.line;
                    if (this.mouse.x && this.mouse.y) {
                        const midX = (this.particles[i].x + this.particles[j].x) / 2;
                        const midY = (this.particles[i].y + this.particles[j].y) / 2;
                        const mouseDist = Math.sqrt(
                            Math.pow(this.mouse.x - midX, 2) +
                            Math.pow(this.mouse.y - midY, 2)
                        );

                        if (mouseDist < this.config.mouseConnectionDistance) {
                            lineColor = this.config.colors.lineActive;
                        }
                    }

                    this.ctx.beginPath();
                    this.ctx.strokeStyle = lineColor.replace('0.15', (opacity * 0.15).toFixed(2))
                        .replace('0.4', (opacity * 0.4).toFixed(2));
                    this.ctx.lineWidth = this.config.lineWidth;
                    this.ctx.moveTo(this.particles[i].x, this.particles[i].y);
                    this.ctx.lineTo(this.particles[j].x, this.particles[j].y);
                    this.ctx.stroke();
                }
            }
        }

        // Conexiones con el mouse
        if (this.mouse.x && this.mouse.y) {
            for (let i = 0; i < this.particles.length; i++) {
                const dx = this.particles[i].x - this.mouse.x;
                const dy = this.particles[i].y - this.mouse.y;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < this.config.mouseConnectionDistance) {
                    const opacity = 1 - (distance / this.config.mouseConnectionDistance);

                    this.ctx.beginPath();
                    this.ctx.strokeStyle = `rgba(0, 255, 200, ${opacity * 0.5})`;
                    this.ctx.lineWidth = this.config.lineWidthActive;
                    this.ctx.moveTo(this.particles[i].x, this.particles[i].y);
                    this.ctx.lineTo(this.mouse.x, this.mouse.y);
                    this.ctx.stroke();
                }
            }

            // Dibujar nodo del cursor
            this.ctx.beginPath();
            this.ctx.arc(this.mouse.x, this.mouse.y, 4, 0, Math.PI * 2);
            this.ctx.fillStyle = this.config.colors.nodeHighlight;
            this.ctx.fill();

            // Glow del cursor
            this.ctx.beginPath();
            this.ctx.arc(this.mouse.x, this.mouse.y, 8, 0, Math.PI * 2);
            this.ctx.strokeStyle = 'rgba(0, 255, 200, 0.3)';
            this.ctx.lineWidth = this.config.lineWidthActive * 2;
            this.ctx.stroke();
        }
    }

    animate() {
        // Usar dimensiones lógicas
        const width = this.width || window.innerWidth;
        const height = this.height || window.innerHeight;

        this.ctx.clearRect(0, 0, width, height);

        // Fondo con gradiente sutil
        const gradient = this.ctx.createRadialGradient(
            width / 2, height / 2, 0,
            width / 2, height / 2, width / 1.5
        );
        gradient.addColorStop(0, 'rgba(15, 15, 20, 0.1)');
        gradient.addColorStop(1, 'rgba(5, 5, 10, 0.1)');
        this.ctx.fillStyle = gradient;
        this.ctx.fillRect(0, 0, width, height);

        this.drawConnections();

        this.particles.forEach(particle => {
            particle.update();
            particle.draw();
        });

        if (this.isRunning) {
            this.animationId = requestAnimationFrame(() => this.animate());
        }
    }

    start() {
        if (!this.isRunning) {
            this.isRunning = true;
            this.animate();
        }
    }

    stop() {
        this.isRunning = false;
        if (this.animationId) {
            cancelAnimationFrame(this.animationId);
        }
    }
}

// Clase Particle (nodos circulares)
class Particle {
    constructor(network) {
        this.network = network;
        this.ctx = network.ctx;
        this.config = network.config;

        // Usar dimensiones lógicas del network
        const width = network.width || window.innerWidth;
        const height = network.height || window.innerHeight;

        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.size = Math.random() * (this.config.particleSize.max - this.config.particleSize.min) + this.config.particleSize.min;
        this.speedX = (Math.random() - 0.5) * this.config.particleSpeed;
        this.speedY = (Math.random() - 0.5) * this.config.particleSpeed;
        this.opacity = Math.random() * 0.5 + 0.3;
    }

    update() {
        // Obtener dimensiones lógicas actuales
        const width = this.network.width || window.innerWidth;
        const height = this.network.height || window.innerHeight;

        // Movimiento básico
        this.x += this.speedX;
        this.y += this.speedY;

        // Interacción con el mouse/touch (repulsión suave)
        if (this.network.mouse.x && this.network.mouse.y) {
            const dx = this.x - this.network.mouse.x;
            const dy = this.y - this.network.mouse.y;
            const distance = Math.sqrt(dx * dx + dy * dy);

            if (distance < this.network.mouse.radius) {
                const force = (this.network.mouse.radius - distance) / this.network.mouse.radius;
                const angle = Math.atan2(dy, dx);
                this.x += Math.cos(angle) * force * 2;
                this.y += Math.sin(angle) * force * 2;
            }
        }

        // Rebote en los bordes usando dimensiones lógicas
        if (this.x < 0 || this.x > width) this.speedX *= -1;
        if (this.y < 0 || this.y > height) this.speedY *= -1;

        // Mantener dentro del canvas
        this.x = Math.max(0, Math.min(width, this.x));
        this.y = Math.max(0, Math.min(height, this.y));
    }

    draw() {
        // Glow effect
        this.ctx.beginPath();
        this.ctx.arc(this.x, this.y, this.size + 2, 0, Math.PI * 2);
        this.ctx.fillStyle = `rgba(255, 255, 255, ${this.opacity * 0.2})`;
        this.ctx.fill();

        // Partícula principal
        this.ctx.beginPath();
        this.ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        this.ctx.fillStyle = `rgba(255, 255, 255, ${this.opacity})`;
        this.ctx.fill();
    }
}

// Clase SquareNode (nodos cuadrados estilo Watch Dogs)
class SquareNode {
    constructor(network) {
        this.network = network;
        this.ctx = network.ctx;
        this.config = network.config;

        // Usar dimensiones lógicas del network
        const width = network.width || window.innerWidth;
        const height = network.height || window.innerHeight;

        // Tamaño adaptativo para móviles
        const baseSize = network.isMobile ? 6 : 8;
        const sizeVariation = network.isMobile ? 4 : 6;

        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.size = Math.random() * sizeVariation + baseSize;
        this.speedX = (Math.random() - 0.5) * 0.2;
        this.speedY = (Math.random() - 0.5) * 0.2;
        this.rotation = Math.random() * Math.PI;
        this.rotationSpeed = (Math.random() - 0.5) * 0.01;
        this.opacity = Math.random() * 0.3 + 0.2;
    }

    update() {
        // Obtener dimensiones lógicas actuales
        const width = this.network.width || window.innerWidth;
        const height = this.network.height || window.innerHeight;

        this.x += this.speedX;
        this.y += this.speedY;
        this.rotation += this.rotationSpeed;

        // Rebote en los bordes usando dimensiones lógicas
        if (this.x < 0 || this.x > width) this.speedX *= -1;
        if (this.y < 0 || this.y > height) this.speedY *= -1;

        this.x = Math.max(0, Math.min(width, this.x));
        this.y = Math.max(0, Math.min(height, this.y));
    }

    draw() {
        this.ctx.save();
        this.ctx.translate(this.x, this.y);
        this.ctx.rotate(this.rotation);

        // Cuadrado con borde - grosor ajustado para HD
        this.ctx.strokeStyle = `rgba(255, 255, 255, ${this.opacity})`;
        this.ctx.lineWidth = this.network.dpr * 0.8;
        this.ctx.strokeRect(-this.size / 2, -this.size / 2, this.size, this.size);

        // Punto central
        this.ctx.beginPath();
        this.ctx.arc(0, 0, 1.5, 0, Math.PI * 2);
        this.ctx.fillStyle = `rgba(255, 255, 255, ${this.opacity * 1.5})`;
        this.ctx.fill();

        this.ctx.restore();
    }
}

// Inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    // Solo inicializar si existe el canvas
    const networkCanvas = document.getElementById('network-bg');
    if (networkCanvas) {
        window.networkBg = new NetworkBackground('network-bg');
    }
});
