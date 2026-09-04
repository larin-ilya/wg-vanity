shader_type canvas_item;
render_mode unshaded;

// wg-vanity v3 — «цифровой шум» поверх всего интерфейса:
// лёгкий анимированный статик (как на старом ЭЛТ-мониторе) + сканлайны.
// Накладывается последним на весь экран; интенсивность/глитч меняются кодом.
// glitch: 0..1 — короткая «полоса помех» (используется в момент находки).

uniform float intensity : hint_range(0.0, 0.5) = 0.05;
uniform float scan_strength : hint_range(0.0, 1.0) = 0.5;
uniform float glitch : hint_range(0.0, 1.0) = 0.0;
uniform float speed : hint_range(0.0, 8.0) = 4.0;

float rnd(vec2 p) {
    p = fract(p * vec2(123.34, 456.21));
    p += dot(p, p + 45.32);
    return fract(p.x * p.y);
}

void fragment() {
    vec2 uv = UV;
    vec3 col = vec3(1.0); // поверх уже отрисованного (смешиваем альфой ниже)
    float t = TIME * speed;

    // зерно: меняющиеся ячейки ~1 пиксель (окно 1240x860)
    vec2 cell = floor(uv * vec2(1240.0, 860.0));
    float n1 = rnd(vec2(cell.x, cell.y + floor(t * 7.0)));
    float n2 = rnd(vec2(cell.y, cell.x + floor(t * 4.0) * 1.7));
    float noise = clamp(n1 * 0.6 + n2 * 0.4, 0.0, 1.0);

    // горизонтальные «волны» сигнала, чтобы статик не был плоским
    float wave = 0.5 + 0.5 * sin(uv.y * 47.0 + floor(t * 5.0) * 2.1
                                 + uv.x * 3.0);
    float grain_a = intensity * noise * (0.35 + 0.65 * wave);

    // сканлайны (тёмные через ~2 px) — рисуем умножением, а не альфой,
    // чтобы не гасить текст ниже; лёгкое мерцание
    float scan = 0.5 + 0.5 * sin(uv.y * 3.14159265 * 430.0 + sin(t * 0.8));
    float scan_dark = scan_strength * 0.5 * (1.0 - scan) * (0.7 + 0.3 * noise);
    // светлая полоска под тёмной (эффект CRT)
    float scan_light = scan_strength * 0.18 * scan
                       * (0.5 + 0.5 * sin(t * 1.3));

    // кратковременный глитч: несколько «рваных» строк, бегущих вниз
    float gl = 0.0;
    if (glitch > 0.001) {
        float row = floor(uv.y * 860.0);
        float pick = rnd(vec2(row, floor(t * 16.0)));
        float thresh = 0.06 + 0.55 * glitch;
        gl = step(1.0 - thresh, pick);
        // короткая яркая вспышка всей строки
        gl *= step(abs(fract(t * 0.7) - uv.y * 0.25), 0.3 * glitch);
    }

    // результирующий цвет: базовый белый, тёмные сканлайны, белый шум,
    // вспышка глитча
    float lum = 1.0 - scan_dark * (1.0 - gl * 0.6);
    float add = grain_a * 0.35 + scan_light * 0.22 + gl * 0.35 * glitch;
    COLOR = vec4(vec3(lum), clamp(add, 0.0, 0.5));
}
