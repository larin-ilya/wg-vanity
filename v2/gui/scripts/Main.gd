extends Node
# Main — приложение wg-vanity v2: красивый GUI + связь с вычислителем.

const Style = preload("res://scripts/Style.gd")

const VERSION = "2.0.0"

enum UState { IDLE, RUNNING, STOPPING }

var ustate = UState.IDLE
var search_id = 0
var cpu = 8
var demo = false
var demo_found_ms = -1.0
var demo_stats_ms = 600.0
var autostart = false
var _bridge: Node
var _shot_file = ""
var _shot_delay = 1500
var _shot_quit = false

# --- UI references ----------------------------------------------------------
var _params_root: Node
var word_edit: LineEdit
var word_hint: Label
var seg_mode: Node
var workers_lbl: Label
var save_toggle: Node
var out_dir_lbl: Label
var fld_endpoint: LineEdit
var fld_pubkey: LineEdit
var fld_dns: LineEdit
var fld_ips: LineEdit
var state_title: Label
var state_sub: Label
var ring: Node
var stat_grid: GridContainer
var idle_hints: Control
var log_rt: RichTextLabel
var overlay: Control
var ov_prefix: Label
var ov_files: Label
var ov_qr: TextureRect
var cfg: ConfigFile
var cfg_path = "user://wg_vanity.cfg"
var exe_dir = ""
var out_dir = ""

# demo/sim state
var _sim_checked = 0
var _sim_elapsed = 0.0
var _sim_peak = 0.0
var _sim_timer: Timer

# --- музыка (лоу-фай WAV через AudioStreamPlayer) ---
var _music: AudioStreamPlayer
var _music_btn: Button
var music_on = true

func _ready() -> void:
	_flog("ready:begin")
	cpu = max(1, OS.get_processor_count())
	exe_dir = OS.get_executable_path().get_base_dir()
	randomize()
	_detect_env()
	_flog("ready:env demo=%s" % demo)
	_build_ui()
	_flog("ready:ui_built")
	_load_settings()
	_apply_settings()
	_setup_music()
	_flog("ready:music=%s" % music_on)
	stat_grid.visible = false
	idle_hints.visible = true
	if not demo:
		_spawn_bridge()
	if demo:
		_log("ДЕМО-режим: вычислитель не запускается", Style.FAINT)
	_setup_autoshot()
	if autostart:
		_timer(0.9, "_on_autostart")
	_flog("ready:end")

var _first_proc = true
func _process(_delta: float) -> void:
	if _first_proc:
		_first_proc = false
		_flog("process:first_tick")

func _flog(s: String) -> void:
	var f = File.new()
	if f.open("user://gd_log.txt", File.WRITE) == OK:
		f.store_line("%d %s" % [OS.get_ticks_msec(), s])
		f.close()


func _build_nodes_report() -> String:
	# быстрый otчёт: сколько Control-узлов построено и не пустая ли колонка
	var parts = []
	for i in range(get_child_count()):
		var c = get_child(i)
		parts.append("%s:%s" % [c.get_class(), str(c.visible)])
	return ",".join(parts)


func _detect_env() -> void:
	demo = OS.get_environment("WG_VANITY_DEMO") == "1"
	var fm = OS.get_environment("WG_VANITY_DEMO_FOUND_MS")
	if fm.is_valid_float():
		demo_found_ms = float(fm)
	var sm = OS.get_environment("WG_VANITY_DEMO_STATS_MS")
	if sm.is_valid_float():
		demo_stats_ms = float(sm)
	autostart = OS.get_environment("WG_VANITY_AUTOSTART") == "1"
	_shot_file = OS.get_environment("WG_VANITY_SHOT_FILE")
	var sd = OS.get_environment("WG_VANITY_SHOT_DELAY")
	if sd.is_valid_integer():
		_shot_delay = int(sd)
	_shot_quit = OS.get_environment("WG_VANITY_SHOT_QUIT") == "1"

func _setup_autoshot() -> void:
	if _shot_file != "":
		_timer(float(_shot_delay) / 1000.0, "_capture_maybe_quit")
	var qms = OS.get_environment("WG_VANITY_QUIT_MS")
	if qms.is_valid_integer():
		_timer(float(int(qms)) / 1000.0, "_force_quit")

func _force_quit() -> void:
	print("WG_FORCE_QUIT")
	get_tree().quit()

func _capture_maybe_quit() -> void:
	print("WG_CAPTURE_BEGIN")
	var img = get_viewport().get_texture().get_data()
	img.flip_y()
	img.save_png(_shot_file)
	print("SHOT_SAVED:", _shot_file)
	if _shot_quit:
		call_deferred("_quit_app")

# ---------------------------------------------------------------------------
#  Сборка интерфейса
# ---------------------------------------------------------------------------
func _build_ui() -> void:
	_flog("build:start")
	var bg = ColorRect.new()
	bg.set_anchors_preset(Control.PRESET_WIDE)
	bg.mouse_filter = Control.MOUSE_FILTER_IGNORE
	bg.color = Color(0.024, 0.031, 0.055)
	var shader = load("res://shaders/bg.gdshader")
	if shader != null:
		var sh = ShaderMaterial.new()
		sh.shader = shader
		bg.material = sh
	add_child(bg)

	var root = Control.new()
	root.set_anchors_preset(Control.PRESET_WIDE)
	add_child(root)

	var margins = MarginContainer.new()
	margins.set_anchors_preset(Control.PRESET_WIDE)
	margins.add_constant_override("margin_left", 24)
	margins.add_constant_override("margin_right", 24)
	margins.add_constant_override("margin_top", 18)
	margins.add_constant_override("margin_bottom", 18)
	root.add_child(margins)

	var col = VBoxContainer.new()
	col.add_constant_override("separation", 14)
	margins.add_child(col)

	col.add_child(_build_header())
	_flog("build:header_done")
	col.add_child(_build_mid())
	_flog("build:mid_done")
	var log_panel = _card("Журнал")
	col.add_child(_card_panel(log_panel))
	_build_log_body(log_panel)
	_flog("build:log_done")

	_build_overlay()
	_flog("build:overlay_done")
	_flog("build:col_children=%d" % get_child_count())
	var bi = _build_nodes_report()
	_flog("build:report=" + bi)

func _build_header() -> Control:
	var hb = HBoxContainer.new()
	hb.rect_min_size = Vector2(0, 56)
	var logo = TextureRect.new()
	var ic: Texture = load("res://assets/icon.png")
	if ic != null:
		logo.texture = ic
	logo.rect_min_size = Vector2(50, 50)
	logo.expand = true
	logo.stretch_mode = TextureRect.STRETCH_KEEP_ASPECT_CENTERED
	hb.add_child(logo)
	var pad = Control.new()
	pad.rect_min_size = Vector2(14, 0)
	hb.add_child(pad)

	var tt = VBoxContainer.new()
	var t1 = Style.label("WG VANITY", 30, Style.TXT, false, true, true)
	tt.add_child(t1)
	var t2 = Style.label("подбор красивых WireGuard-ключей по префиксу", 13, Style.DIM)
	tt.add_child(t2)
	hb.add_child(tt)
	hb.add_child(_hspacer())

	var right = VBoxContainer.new()
	right.alignment = BoxContainer.ALIGN_END
	right.add_constant_override("separation", 4)
	var ver = Style.label("v" + VERSION + "   ·   CPU: " + str(cpu), 12, Style.FAINT)
	right.add_child(ver)
	var mrow = HBoxContainer.new()
	mrow.add_constant_override("separation", 6)
	mrow.alignment = BoxContainer.ALIGN_END
	_music_btn = Style.button("🔊 музыка", 11, false)
	_music_btn.rect_min_size = Vector2(0, 0)
	_music_btn.connect("pressed", self, "_on_music_toggle")
	mrow.add_child(_music_btn)
	mrow.add_child(Style.label("WireGuard · Curve25519 · многопоточный поиск", 11, Style.FAINT))
	right.add_child(mrow)
	hb.add_child(right)
	return hb

func _card(title: String) -> VBoxContainer:
	var panel = PanelContainer.new()
	panel.add_stylebox_override("panel", Style.panel_round(16, Style.PANEL_BG, Style.PANEL_BORDER, 1, 16))
	var pad = MarginContainer.new()
	pad.add_constant_override("margin_left", 16)
	pad.add_constant_override("margin_right", 16)
	pad.add_constant_override("margin_top", 14)
	pad.add_constant_override("margin_bottom", 14)
	panel.add_child(pad)
	var vb = VBoxContainer.new()
	vb.add_constant_override("separation", 12)
	pad.add_child(vb)
	if title != "":
		var head = HBoxContainer.new()
		head.add_constant_override("separation", 9)
		var bar = ColorRect.new()
		bar.color = Style.MINT
		bar.rect_min_size = Vector2(3, 15)
		head.add_child(bar)
		var tl = Style.label(title, 15, Style.TXT, true)
		head.add_child(tl)
		vb.add_child(head)
	return vb

func _card_panel(vb: VBoxContainer) -> Control:
	# vb уже привязан к pad->panel; возвращаем внешний panel, чтобы добавить его
	# в контейнер (иначе "already has a parent" и панель не появится).
	var p = vb.get_parent().get_parent()
	return p as Control

func _build_mid() -> Control:
	var mid = HBoxContainer.new()
	mid.add_constant_override("separation", 16)
	mid.size_flags_vertical = Control.SIZE_EXPAND_FILL

	# --- левая колонка: параметры
	var left = VBoxContainer.new()
	left.rect_min_size = Vector2(452, 0)
	left.size_flags_vertical = Control.SIZE_EXPAND_FILL
	left.add_constant_override("separation", 12)
	mid.add_child(left)
	_params_root = left

	var pc = _card("Параметры поиска")
	left.add_child(_card_panel(pc))

	pc.add_child(Style.label("Слово / префикс", 13, Style.DIM, true))
	word_edit = Style.line_edit("например: lenovo, cook, dark…")
	word_edit.add_font_override("font", Style.font(21, true))
	word_edit.max_length = 34
	word_edit.rect_min_size = Vector2(0, 46)
	word_edit.connect("text_changed", self, "_on_word_changed")
	pc.add_child(word_edit)
	word_hint = Style.label("", 12, Style.FAINT)
	word_hint.autowrap = true
	pc.add_child(word_hint)

	var chips = HFlowContainer.new()
	chips.add_constant_override("hseparation", 6)
	chips.add_constant_override("vseparation", 6)
	pc.add_child(chips)
	for w in ["cook", "test", "vpn", "lenovo", "coin", "dark"]:
		var b = Style.button(w.to_upper(), 11, true)
		b.rect_min_size = Vector2(0, 26)
		chips.add_child(b)
		b.connect("pressed", self, "_on_chip", [w])

	pc.add_child(Style.hsep(Style.PANEL_BORDER, 1, 2))

	pc.add_child(Style.label("Режим подстановок", 13, Style.DIM, true))
	seg_mode = load("res://scripts/Segmented.gd").new()
	pc.add_child(seg_mode)
	seg_mode.set_options(["Обычный — с заменами", "Строгий — точное слово"])
	seg_mode.connect("changed", self, "_on_mode_changed")

	var wrow = HBoxContainer.new()
	wrow.add_constant_override("separation", 10)
	wrow.alignment = BoxContainer.ALIGN_CENTER
	var wcap = Style.label("Ядер для поиска", 13, Style.DIM, true)
	wrow.add_child(wcap)
	var minus = Style.button("−", 18, true)
	minus.rect_min_size = Vector2(34, 32)
	minus.connect("pressed", self, "_on_workers_delta", [-1])
	wrow.add_child(minus)
	workers_lbl = Style.label(str(min(8, cpu)), 20, Style.TXT, true)
	workers_lbl.rect_min_size = Vector2(44, 0)
	workers_lbl.align = Label.ALIGN_CENTER
	wrow.add_child(workers_lbl)
	var plus = Style.button("+", 18, true)
	plus.rect_min_size = Vector2(34, 32)
	plus.connect("pressed", self, "_on_workers_delta", [1])
	wrow.add_child(plus)
	var cpu_lbl = Style.label("из " + str(cpu) + " ядер CPU", 12, Style.FAINT)
	wrow.add_child(cpu_lbl)
	pc.add_child(wrow)

	pc.add_child(Style.hsep(Style.PANEL_BORDER, 1, 2))

	var srow = HBoxContainer.new()
	srow.add_constant_override("separation", 10)
	save_toggle = load("res://scripts/Toggle.gd").new()
	srow.add_child(save_toggle)
	save_toggle.connect("toggled", self, "_toggle_save")
	var sl = Style.label("Сохранять результат в файлы", 14, Style.TXT, true)
	srow.add_child(sl)
	srow.add_child(_hspacer())
	var open_btn = Style.button("Открыть папку", 12, true)
	open_btn.connect("pressed", self, "_on_open_outdir")
	srow.add_child(open_btn)
	pc.add_child(srow)

	var browse = HBoxContainer.new()
	browse.add_constant_override("separation", 8)
	out_dir_lbl = Style.label("", 11, Style.FAINT)
	out_dir_lbl.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	out_dir_lbl.autowrap = true
	browse.add_child(out_dir_lbl)
	var chdir = Style.button("…", 12, true)
	chdir.rect_min_size = Vector2(30, 24)
	chdir.connect("pressed", self, "_on_choose_outdir")
	browse.add_child(chdir)
	pc.add_child(browse)

	pc.add_child(_server_section())

	# --- правая колонка: запуск
	var right = VBoxContainer.new()
	right.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	right.size_flags_vertical = Control.SIZE_EXPAND_FILL
	right.add_constant_override("separation", 12)
	mid.add_child(right)

	var runc = _card("Запуск поиска")
	var runc_panel = _card_panel(runc)
	runc_panel.size_flags_vertical = Control.SIZE_EXPAND_FILL
	right.add_child(runc_panel)

	var body = HBoxContainer.new()
	body.add_constant_override("separation", 18)
	body.size_flags_vertical = Control.SIZE_EXPAND_FILL
	runc.add_child(body)

	var ringcol = VBoxContainer.new()
	ringcol.rect_min_size = Vector2(236, 0)
	ringcol.alignment = BoxContainer.ALIGN_CENTER
	ringcol.add_constant_override("separation", 12)
	body.add_child(ringcol)

	ring = load("res://scripts/RingButton.gd").new()
	ring.rect_min_size = Vector2(148, 148)
	ring.connect("pressed", self, "_on_ring_pressed")
	ringcol.add_child(ring)
	state_title = Style.label("ГОТОВ К ПОИСКУ", 19, Style.TXT, true)
	state_title.align = Label.ALIGN_CENTER
	ringcol.add_child(state_title)
	state_sub = Style.label("введите слово и нажмите кольцо", 12, Style.DIM)
	state_sub.align = Label.ALIGN_CENTER
	state_sub.autowrap = true
	state_sub.rect_min_size = Vector2(216, 0)
	ringcol.add_child(state_sub)

	var stcol = VBoxContainer.new()
	stcol.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	stcol.size_flags_vertical = Control.SIZE_EXPAND_FILL
	stcol.add_constant_override("separation", 10)
	body.add_child(stcol)

	stat_grid = GridContainer.new()
	stat_grid.columns = 2
	stat_grid.add_constant_override("hseparation", 10)
	stat_grid.add_constant_override("vseparation", 10)
	stcol.add_child(stat_grid)

	_tile(stat_grid, "ВРЕМЯ ПОИСКА", "time")
	_tile(stat_grid, "ПРОВЕРЕНО КЛЮЧЕЙ", "checked")
	_tile(stat_grid, "СКОРОСТЬ", "speed")
	_tile(stat_grid, "ОСТАЛОСЬ (ETA)", "eta")
	_set_tile_text("time", "0:00")
	_set_tile_text("checked", "0")
	_set_tile_text("speed", "—")
	_set_tile_text("eta", "—")

	idle_hints = VBoxContainer.new()
	idle_hints.add_constant_override("separation", 8)
	stcol.add_child(idle_hints)
	var tips = [
		"•  Чем короче слово, тем быстрее: 3–5 букв обычно занимают от секунд до пары минут",
		"•  «Обычный» режим пробует похожие символы: a→4, e→3, o→0, s→5…",
		"•  Результат можно сохранить как WireGuard .conf и QR-код для телефона",
	]
	for t in tips:
		var l = Style.label(t, 12, Style.DIM)
		l.autowrap = true
		idle_hints.add_child(l)
	return mid

func _server_section() -> Control:
	var holder = VBoxContainer.new()
	holder.add_constant_override("separation", 8)
	var head = HBoxContainer.new()
	head.add_constant_override("separation", 8)
	head.mouse_filter = Control.MOUSE_FILTER_STOP
	head.mouse_default_cursor_shape = Control.CURSOR_POINTING_HAND
	head.connect("gui_input", self, "_on_server_head_input", [head])
	var arrow = Style.label("▸", 15, Style.DIM)
	head.add_child(arrow)
	head.add_child(Style.label("WireGuard-сервер (для .conf и QR)", 13, Style.TXT, true))
	head.add_child(_hspacer())
	head.add_child(Style.label("развернуть", 11, Style.FAINT))
	holder.add_child(head)

	var body = VBoxContainer.new()
	body.add_constant_override("separation", 8)
	body.visible = false
	holder.add_child(body)
	head.set_meta("body", body)
	head.set_meta("arrow", arrow)

	var rows = [
		["Endpoint сервера", "fld_endpoint", "vpn.example.com:51820"],
		["Публичный ключ сервера", "fld_pubkey", "вставьте ключ…"],
		["DNS", "fld_dns", "1.1.1.1, 8.8.8.8"],
		["AllowedIPs", "fld_ips", "0.0.0.0/0"],
	]
	var fields = {}
	for r in rows:
		body.add_child(Style.label(r[0], 12, Style.DIM))
		var le = Style.line_edit(r[2])
		body.add_child(le)
		fields[r[1]] = le
	fld_endpoint = fields["fld_endpoint"]
	fld_pubkey = fields["fld_pubkey"]
	fld_dns = fields["fld_dns"]
	fld_ips = fields["fld_ips"]

	var note = Style.label("Нужно только при включённом сохранении. Адрес клиента 10.0.0.x/32 подставляется случайно.", 11, Style.FAINT)
	note.autowrap = true
	body.add_child(note)

	var ini_row = HBoxContainer.new()
	ini_row.add_constant_override("separation", 8)
	var b_load = Style.button("Загрузить config.ini", 11, true)
	b_load.connect("pressed", self, "_on_ini_load")
	ini_row.add_child(b_load)
	var b_save = Style.button("Сохранить config.ini", 11, true)
	b_save.connect("pressed", self, "_on_ini_save")
	ini_row.add_child(b_save)
	body.add_child(ini_row)
	return holder

func _on_server_head_input(ev: InputEvent, head: Node) -> void:
	if ev is InputEventMouseButton and ev.button_index == BUTTON_LEFT and ev.pressed:
		var body: Control = head.get_meta("body")
		var arrow: Label = head.get_meta("arrow")
		body.visible = not body.visible
		arrow.text = "▾" if body.visible else "▸"

func _build_log_body(panel_vb: VBoxContainer) -> void:
	var sc = ScrollContainer.new()
	sc.rect_min_size = Vector2(0, 88)
	panel_vb.add_child(sc)
	log_rt = RichTextLabel.new()
	log_rt.bbcode_enabled = true
	log_rt.scroll_following = true
	log_rt.add_font_override("normal_font", Style.font(12))
	log_rt.add_color_override("default_color", Style.DIM)
	log_rt.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	sc.add_child(log_rt)

func _tile(grid: GridContainer, caption: String, key: String) -> void:
	var p = PanelContainer.new()
	p.add_stylebox_override("panel", Style.panel_round(10, Style.PANEL_BG_SOFT, Color(0.10, 0.145, 0.25), 1, 6))
	p.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	p.size_flags_vertical = Control.SIZE_EXPAND_FILL
	var pad = MarginContainer.new()
	pad.add_constant_override("margin_left", 12)
	pad.add_constant_override("margin_right", 12)
	pad.add_constant_override("margin_top", 10)
	pad.add_constant_override("margin_bottom", 10)
	p.add_child(pad)
	var vb = VBoxContainer.new()
	vb.add_constant_override("separation", 2)
	pad.add_child(vb)
	vb.add_child(Style.label(caption, 10, Style.FAINT, true))
	var val = Style.label("—", 19, Style.TXT, true)
	vb.add_child(val)
	p.set_meta("key", key)
	p.set_meta("value", val)
	grid.add_child(p)

func _set_tile_text(key: String, text: String) -> void:
	for child in stat_grid.get_children():
		if child.get_meta("key") == key:
			var v: Label = child.get_meta("value")
			v.text = text
			return

# ---------------------------------------------------------------------------
#  Оверлей результата
# ---------------------------------------------------------------------------
func _build_overlay() -> void:
	overlay = Control.new()
	overlay.set_anchors_preset(Control.PRESET_WIDE)
	overlay.visible = false
	overlay.modulate.a = 1.0
	add_child(overlay)

	var dim = ColorRect.new()
	dim.color = Color(0.012, 0.018, 0.035, 0.82)
	dim.set_anchors_preset(Control.PRESET_WIDE)
	overlay.add_child(dim)

	var center = CenterContainer.new()
	center.set_anchors_preset(Control.PRESET_WIDE)
	overlay.add_child(center)

	var panel = PanelContainer.new()
	panel.add_stylebox_override("panel", Style.panel_round(22, Color(0.052, 0.078, 0.13, 0.99), Color(0.24, 0.36, 0.58), 1, 32))
	panel.rect_min_size = Vector2(800, 0)
	center.add_child(panel)

	var pad = MarginContainer.new()
	pad.add_constant_override("margin_left", 26)
	pad.add_constant_override("margin_right", 26)
	pad.add_constant_override("margin_top", 24)
	pad.add_constant_override("margin_bottom", 24)
	panel.add_child(pad)

	var vb = VBoxContainer.new()
	vb.add_constant_override("separation", 12)
	pad.add_child(vb)

	var head = HBoxContainer.new()
	head.add_constant_override("separation", 12)
	var ok_dot = ColorRect.new()
	ok_dot.color = Style.MINT
	ok_dot.rect_min_size = Vector2(14, 14)
	ok_dot.rect_position = Vector2(0, 6)
	head.add_child(ok_dot)
	head.add_child(Style.label("НАЙДЕН КРАСИВЫЙ КЛЮЧ", 24, Style.TXT, false, true))
	vb.add_child(head)

	ov_prefix = Style.label("", 20, Style.MINT, true)
	vb.add_child(ov_prefix)

	var hbody = HBoxContainer.new()
	hbody.add_constant_override("separation", 18)
	vb.add_child(hbody)

	var lcol = VBoxContainer.new()
	lcol.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	lcol.add_constant_override("separation", 6)
	hbody.add_child(lcol)

	lcol.add_child(_keycard("Публичный ключ клиента", "ov_pub"))
	lcol.add_child(_keycard("Приватный ключ клиента", "ov_priv"))

	var btns = HBoxContainer.new()
	btns.add_constant_override("separation", 8)
	var b1 = Style.accent_button("Копировать приватный", 13)
	b1.connect("pressed", self, "_on_copy_priv")
	btns.add_child(b1)
	var b2 = Style.button("Копировать публичный", 13, true)
	b2.connect("pressed", self, "_on_copy_pub")
	btns.add_child(b2)
	var b3 = Style.button("Открыть папку", 13, true)
	b3.connect("pressed", self, "_on_open_outdir")
	btns.add_child(b3)
	lcol.add_child(btns)

	ov_files = Style.label("", 11, Style.FAINT)
	ov_files.autowrap = true
	lcol.add_child(ov_files)

	var rcol = VBoxContainer.new()
	rcol.rect_min_size = Vector2(244, 0)
	rcol.alignment = BoxContainer.ALIGN_CENTER
	rcol.add_constant_override("separation", 6)
	hbody.add_child(rcol)

	var qrwrap = PanelContainer.new()
	qrwrap.add_stylebox_override("panel", Style.panel_round(12, Color(1, 1, 1, 1), Color(0.9, 0.95, 1, 0.4), 0, 8))
	rcol.add_child(qrwrap)
	ov_qr = TextureRect.new()
	ov_qr.rect_min_size = Vector2(218, 218)
	ov_qr.expand = true
	ov_qr.stretch_mode = TextureRect.STRETCH_KEEP_ASPECT_CENTERED
	qrwrap.add_child(ov_qr)
	rcol.add_child(Style.label("отсканируйте для импорта в приложение", 10, Style.FAINT))

	var actions = HBoxContainer.new()
	actions.add_constant_override("separation", 12)
	actions.alignment = BoxContainer.ALIGN_CENTER
	var anew = Style.accent_button("Новый поиск", 16, Style.MINT)
	anew.rect_min_size = Vector2(200, 44)
	anew.connect("pressed", self, "_on_close_overlay")
	actions.add_child(anew)
	vb.add_child(actions)

	overlay.set_meta("panel", panel)

func _keycard(caption: String, meta_name: String) -> PanelContainer:
	var panel = PanelContainer.new()
	panel.add_stylebox_override("panel", Style.panel_round(10, Color(0.022, 0.035, 0.065, 0.92), Color(0.10, 0.15, 0.27), 1, 4))
	var vb = VBoxContainer.new()
	vb.add_constant_override("separation", 4)
	panel.add_child(vb)
	vb.add_child(Style.label(caption, 11, Style.FAINT, true))
	var val = Style.label("", 13, Style.TXT)
	val.autowrap = true
	vb.add_child(val)
	overlay.set_meta(meta_name, val)
	return panel

# ---------------------------------------------------------------------------
#  Поведение
# ---------------------------------------------------------------------------
func _on_word_changed(_t: String) -> void:
	_update_word_hint()
	_save_settings()

func _on_chip(w: String) -> void:
	word_edit.text = w
	word_edit.grab_focus()
	_update_word_hint()

func _on_mode_changed() -> void:
	_update_word_hint()
	_save_settings()

func _on_workers_delta(d: int) -> void:
	var cur = int(workers_lbl.text)
	cur = clamp(cur + d, 1, cpu)
	workers_lbl.text = str(cur)
	_save_settings()

func _toggle_save(_v: bool) -> void:
	_refresh_outdir_lbl()
	_save_settings()

func _update_word_hint() -> void:
	var w = word_edit.text.strip_edges()
	if w == "":
		word_hint.text = ""
		return
	var strict = seg_mode.get_selected() == 1
	var variants = _count_variants(w, strict)
	var L = w.length()
	var exp_keys = pow(64.0, L) / max(1.0, float(variants))
	var t = "вариантов префиксов: "
	t += _fmt_num(variants)
	t += "  ·  " + ("строгий" if strict else "обычный")
	t += "  ·  в среднем ~%s ключей" % _fmt_num(exp_keys)
	word_hint.text = t

func _fmt_num(v) -> String:
	var x = float(v)
	if x >= 1e12:
		return "%.2f трлн" % (x / 1e12)
	if x >= 1e9:
		return "%.1f млрд" % (x / 1e9)
	if x >= 1e6:
		return "%.1f млн" % (x / 1e6)
	if x >= 1e4:
		return "%s" % Style.fmt_int(int(x))
	return "%s" % Style.fmt_int(int(x))

func _count_variants(w: String, strict: bool) -> float:
	var product = 1.0
	for ch in w:
		var n = 1
		if not strict and _SUBS.has(ch):
			n = _SUBS[ch].size()
		product *= float(n)
	return product

const _SUBS = {
	"a": ["a", "A", "4"], "b": ["b", "B", "8"], "c": ["c", "C"],
	"d": ["d", "D", "9"], "e": ["e", "E", "3"], "f": ["f", "F"],
	"g": ["g", "G", "9", "6"], "h": ["h", "H"], "i": ["i", "I", "1", "l"],
	"j": ["j", "J"], "k": ["k", "K"], "l": ["l", "L", "1", "I"],
	"m": ["m", "M"], "n": ["n", "N"], "o": ["o", "O", "0"],
	"p": ["p", "P"], "q": ["q", "Q"], "r": ["r", "R"],
	"s": ["s", "S", "5"], "t": ["t", "T", "7", "+"], "u": ["u", "U"],
	"v": ["v", "V"], "w": ["w", "W"], "x": ["x", "X"],
	"y": ["y", "Y"], "z": ["z", "Z", "2"],
	"0": ["0", "O", "o"], "1": ["1", "l", "I", "i"], "2": ["2", "z", "Z"],
	"3": ["3", "e", "E"], "4": ["4", "a", "A"], "5": ["5", "s", "S"],
	"6": ["6", "b", "B", "g", "G"], "7": ["7", "T"], "8": ["8", "B"],
	"9": ["9", "g"],
}

func _on_ring_pressed() -> void:
	if ustate == UState.IDLE:
		_start_search()
	elif ustate == UState.RUNNING:
		_stop_search()

func _validate() -> Dictionary:
	var w = word_edit.text.strip_edges()
	if w == "":
		return {"ok": false, "err": "Введите слово для поиска"}
	var allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for ch in w:
		if allowed.find(ch) == -1:
			return {"ok": false, "err": "Недопустимый символ «%s» — только латиница и цифры" % ch}
	if save_toggle.is_on():
		if fld_endpoint.text.strip_edges() == "":
			return {"ok": false, "err": "Укажите Endpoint сервера (или выключите сохранение)"}
		if fld_pubkey.text.strip_edges() == "":
			return {"ok": false, "err": "Вставьте публичный ключ сервера (или выключите сохранение)"}
	return {"ok": true}

func _start_search() -> void:
	var v = _validate()
	if not v.ok:
		_log("⛔ " + str(v.err), Style.DANGER)
		state_sub.text = str(v.err)
		state_sub.add_color_override("font_color", Style.DANGER)
		return
	search_id += 1
	var w = word_edit.text.strip_edges()
	ustate = UState.RUNNING
	_set_inputs_enabled(false)
	ring.set_mode(1)
	idle_hints.visible = false
	stat_grid.visible = true
	state_title.text = "ИДЁТ ПОИСК…"
	state_sub.text = "проверяем ключи на %s ядрах — обычно секунды или минуты" % workers_lbl.text
	state_sub.add_color_override("font_color", Style.CYAN)
	_shown_reset()
	_log("▶ Старт поиска: «%s» · режим: %s · ядер: %s" % [
		w, "строгий" if seg_mode.get_selected() == 1 else "обычный", workers_lbl.text], Style.CYAN)

	var out = out_dir
	if out == "":
		out = exe_dir
	var client_addr = "10.0.0.%d/32" % (31 + randi() % 224)
	var server = {
		"endpoint": fld_endpoint.text.strip_edges(),
		"public_key": fld_pubkey.text.strip_edges(),
		"dns": fld_dns.text.strip_edges(),
		"allowed_ips": fld_ips.text.strip_edges(),
		"client_address": client_addr,
	}
	if demo:
		_demo_start(w, server)
		return
	var msg = {
		"type": "start",
		"search_id": search_id,
		"word": w,
		"strict": seg_mode.get_selected() == 1,
		"workers": int(workers_lbl.text),
		"save": save_toggle.is_on(),
		"out_dir": out,
		"server": server,
	}
	if _bridge != null and _bridge.is_alive():
		_bridge.send(msg)
	else:
		_state_idle("вычислитель не запущен")

func _stop_search() -> void:
	if ustate != UState.RUNNING:
		return
	ustate = UState.STOPPING
	state_title.text = "ОСТАНАВЛИВАЕМ…"
	ring.set_mode(3)
	if demo:
		_demo_stop()
		return
	_bridge.send({"type": "stop", "search_id": search_id})

func _shown_reset() -> void:
	_set_tile_text("time", "0:00")
	_set_tile_text("checked", "0")
	_set_tile_text("speed", "—")
	_set_tile_text("eta", "—")

func _on_autostart() -> void:
	if word_edit.text.strip_edges() == "":
		word_edit.text = "cook"
		_update_word_hint()
	_start_search()

func _on_worker_message(msg: Dictionary) -> void:
	var typ: String = msg.get("type", "")
	match typ:
		"started":
			_log("✔ Поиск запущен · префиксов: %s · ядер: %s" % [
				Style.fmt_int(msg.get("prefix_count", 0)), msg.get("workers", 0)], Style.MINT)
		"stats":
			_on_stats(msg)
		"found":
			_on_found(msg)
		"stopped":
			_log("⏹ Остановлено · проверено ключей: %s" % Style.fmt_int(msg.get("checked", 0)), Style.AMBER)
			_state_idle("поиск остановлен")
		"error":
			_log("⛔ Ошибка вычислителя: " + str(msg.get("message", "?")), Style.DANGER)
			_state_idle("ошибка вычислителя")
		"ready":
			pass

func _on_stats(m: Dictionary) -> void:
	var checked: int = m.get("checked", 0)
	var speed: int = m.get("speed", 0)
	var peak: int = m.get("peak", 0)
	var eta = m.get("eta")
	_set_tile_text("time", Style.fmt_dur(float(m.get("elapsed", 0))))
	_set_tile_text("checked", Style.fmt_int(checked))
	_set_tile_text("speed", "%s/сек · пик %s" % [Style.fmt_int(speed), Style.fmt_int(peak)])
	_set_tile_text("eta", Style.fmt_dur(float(eta)) if eta != null else "—")

func _on_found(m: Dictionary) -> void:
	ustate = UState.IDLE
	_set_inputs_enabled(true)
	ring.set_mode(2)
	state_title.text = "НАЙДЕНО!"
	state_sub.text = "ключ с префиксом " + str(m.get("prefix", ""))
	state_sub.add_color_override("font_color", Style.MINT)
	_set_tile_text("time", Style.fmt_dur(float(m.get("elapsed", 0))))
	_set_tile_text("checked", Style.fmt_int(m.get("checked", 0)))
	_log("🎉 Найден ключ с префиксом «%s»! Проверено: %s · время: %s" % [
		m.get("prefix", ""), Style.fmt_int(m.get("checked", 0)),
		Style.fmt_dur(float(m.get("elapsed", 0)))], Style.MINT)

	ov_prefix.text = "wg:" + str(m.get("prefix", "")) + "   —   публичный ключ начинается с этого префикса"
	var pub: String = m.get("public_key", "")
	var priv: String = m.get("private_key", "")
	(_get_meta_label("ov_pub") as Label).text = pub
	(_get_meta_label("ov_priv") as Label).text = priv
	overlay.set_meta("last_pub", pub)
	overlay.set_meta("last_priv", priv)

	var files: Array = m.get("files", [])
	var lines = []
	for fn in files:
		lines.append("• " + str(fn))
	if files.size() == 0:
		lines.append("сохранение выключено — скопируйте ключи кнопками ниже")
	ov_files.text = "\n".join(lines)

	var qr: String = m.get("qr_png_b64", "")
	_set_qr(qr)
	_show_overlay(true)

func _get_meta_label(key: String) -> Label:
	return overlay.get_meta(key)

func _set_qr(b64: String) -> void:
	ov_qr.texture = null
	if b64 == "":
		if demo:
			var demo_tex: Texture = load("res://assets/demo_qr.png")
			if demo_tex != null:
				ov_qr.texture = demo_tex
		return
	var bytes = Marshalls.base64_to_raw(b64)
	if bytes.size() == 0:
		return
	var img = Image.new()
	var err = img.load_png_from_buffer(bytes)
	if err == OK:
		var tex = ImageTexture.new()
		tex.create_from_image(img)
		ov_qr.texture = tex

func _show_overlay(show: bool) -> void:
	overlay.visible = show
	if show:
		var p: Control = overlay.get_meta("panel")
		p.rect_scale = Vector2(0.96, 0.96)
		var tw = create_tween()
		tw.tween_property(p, "rect_scale", Vector2(1, 1), 0.22) \
			.set_trans(Tween.TRANS_BACK).set_ease(Tween.EASE_OUT)

func _on_close_overlay() -> void:
	_show_overlay(false)
	_state_idle("готов к новому поиску")

func _on_copy_priv() -> void:
	OS.clipboard = str(overlay.get_meta("last_priv", ""))
	_log("📋 Приватный ключ скопирован в буфер", Style.MINT)

func _on_copy_pub() -> void:
	OS.clipboard = str(overlay.get_meta("last_pub", ""))
	_log("📋 Публичный ключ скопирован в буфер", Style.MINT)

func _on_open_outdir() -> void:
	var d = out_dir if out_dir != "" else exe_dir
	if not Directory.new().dir_exists(d):
		d = exe_dir
	OS.shell_open(d)

func _on_choose_outdir() -> void:
	var fd = FileDialog.new()
	fd.mode = FileDialog.MODE_OPEN_DIR
	fd.access = FileDialog.ACCESS_FILESYSTEM
	fd.title = "Папка для сохранения результатов"
	var d = out_dir if out_dir != "" else exe_dir
	if Directory.new().dir_exists(d):
		fd.current_dir = d
	fd.connect("dir_selected", self, "_on_outdir_chosen")
	add_child(fd)
	fd.popup_centered(Vector2(760, 480))

func _on_outdir_chosen(dir: String) -> void:
	out_dir = dir
	_refresh_outdir_lbl()
	_save_settings()

func _refresh_outdir_lbl() -> void:
	var d = out_dir if out_dir != "" else exe_dir
	out_dir_lbl.text = "папка: " + d
	out_dir_lbl.add_color_override("font_color", Style.DIM if out_dir != "" else Style.FAINT)

func _state_idle(sub: String) -> void:
	ustate = UState.IDLE
	_set_inputs_enabled(true)
	ring.set_mode(0)
	state_title.text = "ГОТОВ К ПОИСКУ"
	state_sub.text = sub
	state_sub.add_color_override("font_color", Style.DIM)
	idle_hints.visible = true
	stat_grid.visible = false

func _set_inputs_enabled(on: bool) -> void:
	_dfs_set(_params_root, on)

func _dfs_set(node: Node, on: bool) -> void:
	for c in node.get_children():
		if c is Button:
			c.disabled = not on
		elif c is LineEdit:
			c.editable = on
		elif c.has_method("set_on"):
			c.disabled = not on
		_dfs_set(c, on)

func _on_ini_save() -> void:
	var ini = ConfigFile.new()
	ini.set_value("server", "public_key", fld_pubkey.text.strip_edges())
	ini.set_value("server", "endpoint", fld_endpoint.text.strip_edges())
	ini.set_value("server", "allowed_ips", fld_ips.text.strip_edges())
	ini.set_value("server", "dns", fld_dns.text.strip_edges())
	var p = exe_dir + "/config.ini"
	var err = ini.save(p)
	if err == OK:
		_log("💾 config.ini сохранён рядом с программой", Style.MINT)
	else:
		_log("⛔ Не удалось сохранить config.ini", Style.DANGER)

func _on_ini_load() -> void:
	var p = exe_dir + "/config.ini"
	var ini = ConfigFile.new()
	if ini.load(p) != OK:
		_log("⛔ config.ini рядом с программой не найден", Style.DANGER)
		return
	fld_pubkey.text = str(ini.get_value("server", "public_key", ""))
	fld_endpoint.text = str(ini.get_value("server", "endpoint", ""))
	fld_ips.text = str(ini.get_value("server", "allowed_ips", "0.0.0.0/0"))
	fld_dns.text = str(ini.get_value("server", "dns", "1.1.1.1, 8.8.8.8"))
	_log("📁 config.ini загружен", Style.CYAN)
	_save_settings()

# --- настройки --------------------------------------------------------------
func _load_settings() -> void:
	cfg = ConfigFile.new()
	cfg.load(cfg_path)

func _apply_settings() -> void:
	word_edit.text = str(cfg.get_value("search", "word", ""))
	seg_mode.set_selected(int(cfg.get_value("search", "mode", 0)))
	workers_lbl.text = str(int(cfg.get_value("search", "workers", min(8, cpu))))
	out_dir = str(cfg.get_value("paths", "out_dir", ""))
	music_on = bool(cfg.get_value("settings", "music", true))
	save_toggle.set_on(bool(cfg.get_value("search", "save", false)), true)
	fld_endpoint.text = str(cfg.get_value("server", "endpoint", ""))
	fld_pubkey.text = str(cfg.get_value("server", "public_key", ""))
	fld_dns.text = str(cfg.get_value("server", "dns", "1.1.1.1, 8.8.8.8"))
	fld_ips.text = str(cfg.get_value("server", "allowed_ips", "0.0.0.0/0"))
	_refresh_outdir_lbl()
	_update_word_hint()

func _save_settings() -> void:
	if cfg == null:
		return
	cfg.set_value("search", "word", word_edit.text.strip_edges())
	cfg.set_value("search", "mode", seg_mode.get_selected())
	cfg.set_value("search", "workers", int(workers_lbl.text))
	cfg.set_value("search", "save", save_toggle.is_on())
	cfg.set_value("paths", "out_dir", out_dir)
	cfg.set_value("settings", "music", music_on)
	cfg.set_value("server", "endpoint", fld_endpoint.text.strip_edges())
	cfg.set_value("server", "public_key", fld_pubkey.text.strip_edges())
	cfg.set_value("server", "dns", fld_dns.text.strip_edges())
	cfg.set_value("server", "allowed_ips", fld_ips.text.strip_edges())
	cfg.save(cfg_path)

# --- музыка (MP3 64кбит: .it -> 22кГц моно, лупится через finished) ----
const _MUSIC_MP3 := "res://assets/music/Uctumi_Equanimity.mp3"

func _setup_music() -> void:
	_music_btn.text = "🔈 музыка выкл" if not music_on else "🔊 музыка вкл"
	_music = AudioStreamPlayer.new()
	_music.volume_db = -6.0
	_music.connect("finished", self, "_on_music_finished")
	add_child(_music)
	var s = load(_MUSIC_MP3)
	if s != null:
		_music.stream = s
		# короткая пауза, чтобы GUI успел показаться
		var t := Timer.new()
		t.one_shot = true
		t.wait_time = 0.4
		t.connect("timeout", self, "_play_music_once")
		add_child(t)
		t.start()
	_flog("music:stream=%s playing=%s" % [str(_music.stream), _music.playing])

func _play_music_once() -> void:
	_flog("music:play stream=%s on=%s" % [str(_music.stream), music_on])
	if music_on and _music != null and _music.stream != null:
		_music.play()
		_flog("music:playing=%s" % _music.playing)

func _on_music_finished() -> void:
	# зацикливание
	if music_on:
		_music.play()

func _on_music_toggle() -> void:
	music_on = not music_on
	_flog("music:toggle -> %s" % music_on)
	if music_on:
		_play_music_once()
	else:
		if _music != null:
			_music.stop()
	_music_btn.text = "🔈 музыка выкл" if not music_on else "🔊 музыка вкл"
	_save_settings()

# --- вычислитель ------------------------------------------------------------
func _spawn_bridge() -> void:
	var exe = OS.get_environment("WG_VANITY_WORKER")
	if exe == "" or not File.new().file_exists(exe):
		exe = _resolve_worker_path()
	if exe == "":
		_log("⛔ Вычислитель не найден. Укажите WG_VANITY_WORKER или соберите bundled/wg_worker.exe", Style.DANGER)
		return
	_bridge = load("res://scripts/WorkerBridge.gd").new()
	add_child(_bridge)
	_bridge.connect("message", self, "_on_worker_message")
	_bridge.connect("failed", self, "_on_worker_failed")
	_bridge.connect("connected", self, "_on_worker_connected")
	_log("▶ Запуск вычислителя…", Style.FAINT)
	_flog("spawn:worker_exe=%s" % exe)
	_bridge.launch(exe)
	_flog("spawn:launch_called pid=%d" % _bridge.get_pid())

func _resolve_worker_path() -> String:
	var sidecar = exe_dir + "/wg_worker.exe"
	if File.new().file_exists(sidecar):
		return sidecar
	return _extract_embedded_worker()

func _extract_embedded_worker() -> String:
	var res = "res://bundled/wg_worker.exe"
	if not File.new().file_exists(res):
		return ""
	var dir = OS.get_user_data_dir() + "/wgv_" + str(OS.get_unix_time())
	Directory.new().make_dir_recursive(dir)
	var target = dir + "/wg_worker.exe"
	var f = File.new()
	if f.open(res, File.READ) != OK:
		return ""
	var bytes = f.get_buffer(f.get_len())
	f.close()
	var w = File.new()
	if w.open(target, File.WRITE) != OK:
		return ""
	w.store_buffer(bytes)
	w.close()
	return target

func _on_worker_connected() -> void:
	_log("✔ Вычислитель готов", Style.MINT)

func _on_worker_failed(reason: String) -> void:
	_log("⛔ " + reason, Style.DANGER)
	if ustate == UState.RUNNING:
		_state_idle("вычислитель не запустился")

func _quit_app() -> void:
	if _bridge != null and _bridge.is_alive():
		_bridge.shutdown()
	get_tree().quit()

func _notification(what: int) -> void:
	if what == NOTIFICATION_WM_QUIT_REQUEST:
		_save_settings()
		_quit_app()

# --- helpers ----------------------------------------------------------------
func _hspacer() -> Control:
	var c = Control.new()
	c.size_flags_horizontal = Control.SIZE_EXPAND_FILL
	return c

func _timer(sec: float, method: String) -> Timer:
	var t = Timer.new()
	t.one_shot = true
	t.wait_time = sec
	t.connect("timeout", self, method)
	add_child(t)
	t.start()
	return t

func _log(text: String, color = Style.DIM) -> void:
	var c = color.to_html()
	log_rt.append_bbcode("[color=#" + c + "]" + text + "[/color]\n")

# --- demo-режим -------------------------------------------------------------
func _demo_start(_w: String, _server: Dictionary) -> void:
	_log("✔ [демо] Поиск запущен", Style.MINT)
	_sim_checked = 0
	_sim_elapsed = 0.0
	_sim_peak = 0.0
	if _sim_timer != null and is_instance_valid(_sim_timer):
		_sim_timer.queue_free()
	_sim_timer = _timer(demo_stats_ms / 1000.0, "_demo_stats")
	if demo_found_ms > 0:
		_timer(demo_found_ms / 1000.0, "_demo_found")

func _demo_stats() -> void:
	if ustate != UState.RUNNING:
		return
	_sim_checked += 1200 + randi() % 2600
	_sim_elapsed += demo_stats_ms / 1000.0
	var spd = 1400 + randi() % 2200
	_sim_peak = max(_sim_peak, float(spd))
	_on_stats({
		"checked": _sim_checked, "speed": spd, "peak": int(_sim_peak),
		"elapsed": _sim_elapsed, "eta": 64 - min(60.0, _sim_elapsed),
	})
	_sim_timer = _timer(demo_stats_ms / 1000.0, "_demo_stats")

func _demo_found() -> void:
	if ustate != UState.RUNNING:
		return
	var w = word_edit.text.strip_edges()
	if w == "":
		w = "demo"
	_on_found({
		"prefix": w,
		"public_key": _fake_b64(),
		"private_key": _fake_b64(),
		"checked": _sim_checked,
		"elapsed": _sim_elapsed,
		"worker_id": 1,
		"files": [
			"wg_%s_%s_20260903_120000.conf" % [w, w],
			"wg_%s_%s_20260903_120000_keys.txt" % [w, w],
			"wg_%s_%s_20260903_120000_qr.png" % [w, w],
			"wg_keys_log.txt",
		],
		"qr_png_b64": "",
	})

func _demo_stop() -> void:
	_on_worker_message({"type": "stopped", "checked": _sim_checked, "elapsed": _sim_elapsed})

func _fake_b64() -> String:
	var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var s = ""
	for i in range(43):
		s += chars[randi() % 64]
	return s + "="
