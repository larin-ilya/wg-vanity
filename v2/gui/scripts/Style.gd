class_name Style
extends Object

# --- Палитра ---
const MINT = Color(0.16, 0.92, 0.70)
const MINT_DARK = Color(0.08, 0.55, 0.44)
const CYAN = Color(0.35, 0.86, 1.0)
const BLUE = Color(0.38, 0.63, 1.0)
const VIOLET = Color(0.60, 0.45, 1.0)
const DANGER = Color(1.0, 0.36, 0.45)
const DANGER_DARK = Color(0.62, 0.13, 0.20)
const AMBER = Color(1.0, 0.72, 0.33)

const PANEL_BG = Color(0.043, 0.063, 0.105, 0.94)
const PANEL_BG_SOFT = Color(0.055, 0.078, 0.125, 0.86)
const PANEL_BORDER = Color(0.13, 0.18, 0.29)
const PANEL_BORDER_BRIGHT = Color(0.20, 0.30, 0.48)
const FIELD_BG = Color(0.020, 0.031, 0.058, 0.9)
const FIELD_BORDER = Color(0.14, 0.21, 0.36)

const TXT = Color(0.93, 0.955, 1.0)
const DIM = Color(0.60, 0.69, 0.86)
const FAINT = Color(0.40, 0.48, 0.66)
const TXT_ON_ACCENT = Color(0.015, 0.05, 0.045)
const SHADOW = Color(0.0, 0.0, 0.0, 0.45)

# --- Шрифты --------------------------------------------------------------
static func font(size: int, bold = false, display = false) -> DynamicFont:
	var f = DynamicFont.new()
	f.size = size
	f.use_filter = true
	f.font_data = _font_data(bold, display)
	return f

# Загрузка шрифта с фолбэком:
#  1) проектный .ttf (res://) — красивые Play/RussoOne, если присутствуют;
#  2) системный Arial (C:/Windows/Fonts) — гарантированно работает в экспорте
#     и содержит кириллицу (как в HorrorStation).
static func _font_data(bold: bool, display: bool) -> DynamicFontData:
	var cands = []
	if display:
		cands = ["res://assets/fonts/RussoOne-Regular.ttf",
				"C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"]
	elif bold:
		cands = ["res://assets/fonts/Play-Bold.ttf",
				"C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/arial.ttf"]
	else:
		cands = ["res://assets/fonts/Play-Regular.ttf",
				"C:/Windows/Fonts/arial.ttf"]
	var chosen = null
	for p in cands:
		if File.new().file_exists(p):
			chosen = p
			break
	var fd = DynamicFontData.new()
	fd.font_path = chosen if chosen != null else "C:/Windows/Fonts/arial.ttf"
	return fd

# --- StyleBox'ы ----------------------------------------------------------
static func panel_round(radius = 16, bg = PANEL_BG, border = PANEL_BORDER,
		border_w = 1, shadow_size = 14) -> StyleBoxFlat:
	var sb = StyleBoxFlat.new()
	sb.bg_color = bg
	sb.border_color = border
	sb.set_border_width_all(border_w)
	sb.set_corner_radius_all(radius)
	sb.shadow_color = SHADOW
	sb.shadow_size = shadow_size
	return sb

static func button_style(bg: Color, border: Color, radius = 9) -> StyleBoxFlat:
	var sb = StyleBoxFlat.new()
	sb.bg_color = bg
	sb.border_color = border
	sb.set_border_width_all(1)
	sb.set_corner_radius_all(radius)
	sb.content_margin_left = 14
	sb.content_margin_right = 14
	sb.content_margin_top = 7
	sb.content_margin_bottom = 7
	return sb

static func field_style() -> StyleBoxFlat:
	var sb = StyleBoxFlat.new()
	sb.bg_color = FIELD_BG
	sb.border_color = FIELD_BORDER
	sb.set_border_width_all(1)
	sb.set_corner_radius_all(8)
	sb.content_margin_left = 12
	sb.content_margin_right = 12
	sb.content_margin_top = 8
	sb.content_margin_bottom = 8
	return sb

static func field_focus_style() -> StyleBoxFlat:
	var sb = field_style()
	sb.border_color = MINT
	sb.set_border_width_all(1)
	return sb

# --- Фабрики элементов ---------------------------------------------------
static func label(text: String, size = 15, color = TXT, bold = false,
		display = false, shadow = false) -> Label:
	var l = Label.new()
	l.text = text
	l.add_font_override("font", font(size, bold, display))
	l.add_color_override("font_color", color)
	if shadow:
		l.add_color_override("font_color_shadow", Color(0, 0, 0, 0.55))
		l.add_constant_override("shadow_offset_x", 1)
		l.add_constant_override("shadow_offset_y", 2)
	return l

static func button(text: String, size = 14, bold = true) -> Button:
	var b = Button.new()
	b.text = text
	b.add_font_override("font", font(size, bold))
	b.add_color_override("font_color", TXT)
	b.add_color_override("font_hover_color", TXT)
	b.add_color_override("font_pressed_color", TXT)
	b.add_color_override("font_disabled_color", FAINT)
	b.add_color_override("font_hover_pressed_color", TXT)
	b.add_stylebox_override("normal", button_style(PANEL_BG_SOFT, PANEL_BORDER, 8))
	b.add_stylebox_override("hover", button_style(Color(0.07, 0.10, 0.17), Color(0.22, 0.34, 0.55), 8))
	b.add_stylebox_override("pressed", button_style(Color(0.09, 0.13, 0.22), MINT_DARK, 8))
	b.add_stylebox_override("hover_pressed", button_style(Color(0.09, 0.13, 0.22), MINT_DARK, 8))
	b.add_stylebox_override("focus", StyleBoxEmpty.new())
	b.add_stylebox_override("disabled", button_style(Color(0.03, 0.045, 0.08), Color(0.06, 0.08, 0.13), 8))
	return b

static func accent_button(text: String, size = 15, bg = MINT, fg = TXT_ON_ACCENT) -> Button:
	var b = Button.new()
	b.text = text
	b.add_font_override("font", font(size, true))
	b.add_color_override("font_color", fg)
	b.add_color_override("font_hover_color", fg)
	b.add_color_override("font_pressed_color", fg)
	b.add_color_override("font_disabled_color", Color(0.5, 0.6, 0.6, 0.5))
	var nb = button_style(bg, Color(1, 1, 1, 0.12), 9)
	var hb = button_style(bg.lightened(0.12), Color(1, 1, 1, 0.22), 9)
	var pb = button_style(bg.darkened(0.16), Color(1, 1, 1, 0.1), 9)
	b.add_stylebox_override("normal", nb)
	b.add_stylebox_override("hover", hb)
	b.add_stylebox_override("pressed", pb)
	b.add_stylebox_override("hover_pressed", pb)
	b.add_stylebox_override("focus", StyleBoxEmpty.new())
	return b

static func line_edit(placeholder = "", secret = false) -> LineEdit:
	var le = LineEdit.new()
	le.placeholder_text = placeholder
	le.secret = secret
	le.add_font_override("font", font(15, false))
	le.add_color_override("font_color", TXT)
	le.add_color_override("font_placeholder_color", FAINT)
	le.add_color_override("caret_color", MINT)
	le.add_color_override("selection_color", Color(0.16, 0.5, 0.42, 0.5))
	le.add_color_override("font_uneditable_color", DIM)
	le.add_stylebox_override("normal", field_style())
	le.add_stylebox_override("focus", field_focus_style())
	le.add_stylebox_override("read_only", field_style())
	le.caret_blink = true
	return le

static func hsep(color = PANEL_BORDER, h = 1, margin_v = 0) -> Control:
	var cr = ColorRect.new()
	cr.color = color
	cr.rect_min_size = Vector2(0, h)
	if margin_v > 0:
		var m = MarginContainer.new()
		m.add_constant_override("margin_top", margin_v)
		m.add_constant_override("margin_bottom", margin_v)
		m.add_child(cr)
		return m
	return cr

static func fmt_int(v) -> String:
	var s = str(int(v))
	var out = ""
	var cnt = 0
	for i in range(s.length() - 1, -1, -1):
		out = s[i] + out
		cnt += 1
		if cnt % 3 == 0 and i > 0:
			out = "\u202f" + out
	return out

static func fmt_dur(sec: float) -> String:
	sec = max(0, int(sec))
	var h = int(sec) / 3600
	var m = (int(sec) % 3600) / 60
	var s = int(sec) % 60
	if h > 0:
		return "%d:%02d:%02d" % [h, m, s]
	return "%02d:%02d" % [m, s]
