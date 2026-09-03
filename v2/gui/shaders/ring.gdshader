shader_type canvas_item;
render_mode unshaded;

// wg-vanity v2 — кольцевая кнопка запуска: светящееся кольцо с прогрессом.
// mode: 0 = idle (готов), 1 = running (поиск), 2 = found (победа), 3 = danger/stop

uniform vec4 col_ring : hint_color = vec4(0.22, 0.95, 0.76, 1.0);
uniform vec4 col_ring_b : hint_color = vec4(0.36, 0.65, 1.0, 1.0);
uniform vec4 col_glow : hint_color = vec4(0.22, 0.95, 0.76, 1.0);
uniform vec4 col_core : hint_color = vec4(0.035, 0.055, 0.10, 0.92);
uniform float progress : hint_range(0.0, 1.0) = 0.0;
uniform float mode : hint_range(0.0, 3.0) = 0.0;
uniform float thickness : hint_range(0.01, 0.35) = 0.11;
uniform float pulse : hint_range(0.0, 1.0) = 0.0; // дыхание (0..1)
uniform float wobble : hint_range(0.0, 1.0) = 0.0; // вращение «свечения» при поиске

float ring_band(vec2 p, float r0, float r1) {
    float r = length(p);
    float in_a = 1.0 - smoothstep(r1 - 0.0025, r1 + 0.0025, r);
    float in_b = smoothstep(r0 - 0.0025, r0 + 0.0025, r);
    return in_a * in_b;
}

float arc(vec2 p, float a0, float a1) {
    float ang = atan(p.y, p.x);
    ang = mod(ang, 6.2831853);
    a0 = mod(a0, 6.2831853);
    a1 = mod(a1, 6.2831853);
    if (a0 <= a1) {
        return step(a0, ang) * (1.0 - step(a1, ang));
    } else {
        return step(a0, ang) + (1.0 - step(a1, ang));
    }
}

void fragment() {
    vec2 uv = UV;
    vec2 p = uv - 0.5;
    float r = length(p);
    float r0 = 0.5 - thickness;
    float r1 = 0.5 - 0.004;
    float band = ring_band(p, r0, r1);

    vec3 col = vec3(0.0);
    float alpha = 0.0;

    // сердцевина-диск (тёмная, с лёгким внутренним свечением)
    float coreA = 1.0 - smoothstep(r0 + 0.012, r0 - 0.03, r);
    coreA = clamp(coreA, 0.0, 1.0);
    col += col_core.rgb * coreA * 0.96;
    alpha = max(alpha, coreA * col_core.a);

    // свечение под кольцом
    float glow_r = 0.5 + 0.075 + pulse * 0.03;
    float ga = exp(-pow(r - 0.5, 2.0) * 320.0);
    ga *= (0.35 + pulse * 0.5);
    col += col_glow.rgb * ga * band + col_glow.rgb * ga * 0.4 * (1.0 - band);
    alpha = max(alpha, ga * 0.55);

    // база кольца — тонкая тёмно-синяя, по состоянию подкрашенная
    vec3 base_col = mix(vec3(0.10, 0.16, 0.27), col_ring.rgb, 0.25);
    float start = -1.5707963; // сверху
    if (mode > 0.5 && mode < 2.5) {
        // running: тёмная база + бегущий сегмент прогресса
        col += base_col * band * 0.9;
        alpha = max(alpha, band * 0.9);
        // бегущий огонёк
        float apos = start + wobble * 6.2831853;
        float trail = arc(p, apos - 0.7, apos);
        col += col_ring.rgb * trail * band * 1.1;
        alpha = max(alpha, trail * band);
        // «хвост» прогресса
        float pr = clamp(progress, 0.0, 1.0);
        float sweep = arc(p, start, start + pr * 6.2831853);
        col += col_ring.rgb * sweep * band * 0.85;
        alpha = max(alpha, sweep * band * 0.85);
        // светящаяся точка на конце прогресса
        vec2 tip = vec2(cos(start + pr * 6.2831853), sin(start + pr * 6.2831853)) * (r0 + r1) * 0.5;
        float tipd = distance(p, tip);
        col += col_ring.rgb * exp(-tipd * tipd * 260.0);
        alpha = max(alpha, exp(-tipd * tipd * 260.0));
    } else {
        // idle/found: цельное кольцо с градиентом по окружности
        float angn = atan(p.y, p.x) / 6.2831853 + 0.5;
        vec3 ring_grad = mix(col_ring.rgb, col_ring_b.rgb, smoothstep(0.0, 1.0, angn));
        float br = 0.75 + 0.25 * pulse;
        col += ring_grad * band * br;
        alpha = max(alpha, band * br);
        // яркая точка-блик сверху
        vec2 bp = vec2(0.0, -(r0 + r1) * 0.5);
        float bd = distance(p, bp);
        col += vec3(1.0, 1.0, 0.92) * exp(-bd * bd * 300.0) * band;
    }

    COLOR = vec4(col, alpha);
}
