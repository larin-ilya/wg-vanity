shader_type canvas_item;
render_mode unshaded;

// wg-vanity v2 — анимированный фон: тёмный градиент + цветные «ауры»
uniform vec4 col_top : hint_color = vec4(0.016, 0.024, 0.043, 1.0);
uniform vec4 col_bottom : hint_color = vec4(0.035, 0.059, 0.110, 1.0);

uniform vec4 aura1 : hint_color = vec4(0.18, 0.93, 0.71, 1.0);
uniform vec4 aura2 : hint_color = vec4(0.30, 0.60, 1.0, 1.0);
uniform vec4 aura3 : hint_color = vec4(0.72, 0.42, 1.0, 1.0);

uniform float aura_intensity : hint_range(0.0, 1.0) = 0.55;
uniform float speed : hint_range(0.0, 2.0) = 0.6;

float hash21(vec2 p) {
    p = fract(p * vec2(234.34, 435.345));
    p += dot(p, p + 34.23);
    return fract(p.x * p.y);
}

void fragment() {
    vec2 uv = UV;
    // градиент фона
    vec3 col = mix(col_top.rgb, col_bottom.rgb, pow(uv.y, 0.9));
    float t = TIME * speed;

    // аура 1 (mint) — левый верх, медленно плывёт
    vec2 p1 = vec2(0.16 + 0.06 * sin(t * 0.7), 0.10 + 0.05 * cos(t * 0.5));
    float d1 = distance(uv, p1);
    col += aura1.rgb * aura_intensity * exp(-d1 * d1 * 6.5);

    // аура 2 (blue) — правый низ
    vec2 p2 = vec2(0.86 + 0.05 * sin(t * 0.4 + 1.7), 0.86 + 0.06 * cos(t * 0.6));
    float d2 = distance(uv, p2);
    col += aura2.rgb * aura_intensity * exp(-d2 * d2 * 5.0);

    // аура 3 (violet) — центр/середина слева, слабая
    vec2 p3 = vec2(0.35 + 0.10 * sin(t * 0.3 + 4.0), 0.55 + 0.08 * cos(t * 0.45));
    float d3 = distance(uv, p3);
    col += aura3.rgb * (aura_intensity * 0.55) * exp(-d3 * d3 * 8.0);

    // едва заметный «шум»
    float n = hash21(uv * 800.0 + fract(t) * 0.5);
    col += (n - 0.5) * 0.012;

    // виньетка
    vec2 vc = uv - 0.5;
    float vig = smoothstep(0.9, 0.35, length(vc) * 1.35);
    col *= mix(0.72, 1.0, vig);

    COLOR = vec4(col, 1.0);
}
