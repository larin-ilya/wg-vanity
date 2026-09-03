extends Control
# Toggle — красивый переключатель (ON/OFF) с анимацией.
# ВАЖНО: никаких preload других скриптов — чтобы не ломать парсер Godot 3
# при вложенной компиляции (инлайн-константы вместо Style).

signal toggled

const _C_MINT_DARK = Color(0.08, 0.55, 0.44)
const _C_BORDER = Color(0.2, 0.25, 0.36)

var _on = false
var _knob = 0.0  # 0..1 позиция ручки
var _w = 46.0
var _h = 24.0
var disabled = false

func _ready() -> void:
	rect_min_size = Vector2(_w, _h)
	mouse_default_cursor_shape = Control.CURSOR_POINTING_HAND
	_knob = 1.0 if _on else 0.0

func is_on() -> bool:
	return _on

func set_on(v: bool, silent = false) -> void:
	_on = v
	if not silent:
		emit_signal("toggled", _on)

func _process(delta: float) -> void:
	var target = 1.0 if _on else 0.0
	_knob = lerp(_knob, target, min(1.0, delta * 14.0))
	update()

func _draw() -> void:
	var r = Rect2(0, 0, _w, _h)
	var radius = _h * 0.5
	var bg = Color(0.045, 0.065, 0.11)
	if disabled:
		bg = Color(0.03, 0.04, 0.06)
	if _on:
		bg = Color(0.10, 0.45, 0.35) if disabled else _C_MINT_DARK.lightened(0.15)
	draw_style_box(_body_sb(bg, radius), r)
	var kx = lerp(radius + 2.0, _w - radius - 2.0, _knob)
	var kc = Color(0.85, 0.9, 1.0) if not disabled else Color(0.45, 0.5, 0.6)
	draw_circle(Vector2(kx, _h * 0.5), radius - 4.0, kc)
	draw_circle(Vector2(kx - 1.5, _h * 0.5 - 2.0), (radius - 4.0) * 0.35,
			Color(1, 1, 1, 0.5))

func _body_sb(bg: Color, radius: float) -> StyleBoxFlat:
	var sb = StyleBoxFlat.new()
	sb.bg_color = bg
	sb.set_corner_radius_all(int(radius))
	sb.border_color = _C_BORDER
	sb.set_border_width_all(1)
	return sb

func _gui_input(ev: InputEvent) -> void:
	if disabled:
		return
	if ev is InputEventMouseButton and ev.button_index == BUTTON_LEFT and ev.pressed:
		set_on(not _on)
