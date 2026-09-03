extends PanelContainer
# Segmented — сегментный переключатель (как в современных приложениях).
# ВАЖНО: без preload других скриптов (см. Toggle.gd) — инлайн-константы.

signal changed

const _MINT = Color(0.16, 0.92, 0.70)
const _TXT_ON = Color(0.015, 0.05, 0.045)
const _DIM = Color(0.60, 0.69, 0.86)
const _TXT = Color(0.93, 0.955, 1.0)

var options = []
var _buttons = []
var _hbox: HBoxContainer
var _selected = 0

func _ready() -> void:
	add_stylebox_override("panel", _seg_sb())
	_hbox = HBoxContainer.new()
	_hbox.add_constant_override("separation", 4)
	add_child(_hbox)
	_build_buttons()

func _build_buttons() -> void:
	for i in range(options.size()):
		var b = Button.new()
		b.text = options[i]
		b.add_font_override("font", _font(13, true))
		b.size_flags_horizontal = Control.SIZE_EXPAND_FILL
		b.add_stylebox_override("focus", StyleBoxEmpty.new())
		b.connect("pressed", self, "_on_pressed", [i])
		_hbox.add_child(b)
		_buttons.append(b)
	_select(0)

func _font(size: int, bold = false) -> DynamicFont:
	return Style.font(size, bold)

func _seg_sb() -> StyleBoxFlat:
	var sb = StyleBoxFlat.new()
	sb.bg_color = Color(0.020, 0.031, 0.058, 0.95)
	sb.border_color = Color(0.10, 0.16, 0.28)
	sb.set_border_width_all(1)
	sb.set_corner_radius_all(9)
	return sb

func _pill(bg: Color) -> StyleBoxFlat:
	var sb = StyleBoxFlat.new()
	sb.bg_color = bg
	sb.set_corner_radius_all(6)
	sb.content_margin_left = 8
	sb.content_margin_right = 8
	sb.content_margin_top = 6
	sb.content_margin_bottom = 6
	return sb

func set_options(opts: Array) -> void:
	options = opts
	if _hbox == null:
		return
	for b in _buttons:
		b.queue_free()
	_buttons.clear()
	_build_buttons()

func get_selected() -> int:
	return _selected

func set_selected(i: int) -> void:
	_select(i)

func _on_pressed(i: int) -> void:
	_select(i)
	emit_signal("changed")

func _select(i: int) -> void:
	_selected = i
	for j in range(_buttons.size()):
		var b: Button = _buttons[j]
		if j == i:
			b.add_stylebox_override("normal", _pill(_MINT))
			b.add_stylebox_override("hover", _pill(_MINT.lightened(0.1)))
			b.add_stylebox_override("pressed", _pill(_MINT.darkened(0.1)))
			b.add_stylebox_override("hover_pressed", b.get_stylebox("pressed"))
			b.add_color_override("font_color", _TXT_ON)
			b.add_color_override("font_hover_color", _TXT_ON)
			b.add_color_override("font_pressed_color", _TXT_ON)
		else:
			b.add_stylebox_override("normal", StyleBoxEmpty.new())
			b.add_stylebox_override("hover", _pill(Color(0.08, 0.12, 0.2)))
			b.add_stylebox_override("pressed", _pill(Color(0.05, 0.08, 0.14)))
			b.add_stylebox_override("hover_pressed", b.get_stylebox("pressed"))
			b.add_color_override("font_color", _DIM)
			b.add_color_override("font_hover_color", _TXT)
			b.add_color_override("font_pressed_color", _DIM)
