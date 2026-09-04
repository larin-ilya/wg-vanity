extends Control
# RingButton — большая круглая кнопка запуска с шейдерным кольцом.
# mode: 0 idle | 1 running | 2 found | 3 danger
# ВАЖНО: без preload других скриптов (см. Toggle.gd) — инлайн-константы.

signal pressed

const _MINT = Color(0.16, 0.92, 0.70)
const _BLUE = Color(0.38, 0.63, 1.0)
const _CYAN = Color(0.35, 0.86, 1.0)
const _DANGER = Color(1.0, 0.36, 0.45)
const _GOLD = Color(1.0, 0.88, 0.35)

var _mat: ShaderMaterial
var _mat_ok = false
var _lbl: Label
var _cc: CenterContainer
var _t = 0.0
var _wob = 0.0
var mode = 0
var label_text = "СТАРТ"
var _col_ring = _MINT
var _col_ring_b = _BLUE
var _col_glow = _MINT

func _ready() -> void:
	rect_min_size = Vector2(150, 150)
	mouse_default_cursor_shape = Control.CURSOR_POINTING_HAND
	var shader = load("res://shaders/ring.gdshader")
	_mat = ShaderMaterial.new()
	_mat.shader = shader
	_mat_ok = shader != null
	var cr = ColorRect.new()
	cr.material = _mat
	cr.set_anchors_preset(Control.PRESET_WIDE)
	cr.mouse_filter = Control.MOUSE_FILTER_IGNORE
	cr.color = Color(1, 1, 1, 1)
	add_child(cr)
	_cc = CenterContainer.new()
	_cc.set_anchors_preset(Control.PRESET_WIDE)
	_cc.mouse_filter = Control.MOUSE_FILTER_IGNORE
	add_child(_cc)
	_lbl = _mk_label("СТАРТ", 19)
	_cc.add_child(_lbl)
	_update_uniforms()

func _mk_label(text: String, size: int) -> Label:
	var l = Label.new()
	l.text = text
	l.mouse_filter = Control.MOUSE_FILTER_IGNORE
	var f = Style.font(size, true)
	l.add_font_override("font", f)
	l.add_color_override("font_color", Color(0.95, 1.0, 1.0))
	l.add_color_override("font_color_shadow", Color(0, 0, 0, 0.5))
	l.add_constant_override("shadow_offset_x", 1)
	l.add_constant_override("shadow_offset_y", 2)
	return l

func _process(delta: float) -> void:
	_t += delta
	if not _mat_ok:
		return
	var pulse = 0.5 + 0.5 * sin(_t * 2.2)
	if mode == 1:
		_wob = fmod(_wob + delta * 1.25, 1.0)
		_mat.set_shader_param("wobble", _wob)
	elif mode == 2:
		pulse = 0.5 + 0.5 * sin(_t * 4.5)
	else:
		pulse = 0.5 + 0.5 * sin(_t * 1.6 + 0.8)
	_mat.set_shader_param("pulse", pulse)

func _update_uniforms() -> void:
	if not _mat_ok:
		return
	_mat.set_shader_param("col_ring", _col_ring)
	_mat.set_shader_param("col_ring_b", _col_ring_b)
	_mat.set_shader_param("col_glow", _col_glow)
	_mat.set_shader_param("mode", float(mode))
	_mat.set_shader_param("progress", 0.0)

func set_mode(m: int) -> void:
	mode = m
	match m:
		0:
			_col_ring = _MINT
			_col_ring_b = _BLUE
			_col_glow = _MINT
			set_text("СТАРТ")
		1:
			_col_ring = _MINT
			_col_ring_b = _CYAN
			_col_glow = _CYAN
			set_text("СТОП")
		2:
			_col_ring = _GOLD
			_col_ring_b = _MINT
			_col_glow = _GOLD
			set_text("ЕЩЁ")
		3:
			_col_ring = _DANGER
			_col_ring_b = Color(1.0, 0.6, 0.5)
			_col_glow = _DANGER
			set_text("СТОП")
	_update_uniforms()

func set_progress(p: float) -> void:
	if _mat_ok:
		_mat.set_shader_param("progress", clamp(p, 0.0, 1.0))

func set_text(t: String) -> void:
	label_text = t
	if _lbl != null:
		_lbl.text = t

func _gui_input(ev: InputEvent) -> void:
	if ev is InputEventMouseButton and ev.button_index == BUTTON_LEFT:
		if ev.pressed:
			modulate = Color(0.92, 0.96, 1.0, 1.0)
			emit_signal("pressed")

func _notification(what: int) -> void:
	if what == NOTIFICATION_MOUSE_ENTER:
		modulate = Color(1.06, 1.06, 1.1, 1.0)
	elif what == NOTIFICATION_MOUSE_EXIT:
		modulate = Color(1, 1, 1, 1)
