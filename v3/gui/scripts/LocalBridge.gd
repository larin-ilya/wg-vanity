extends Node
# LocalBridge — поиск ВНУТРИ приложения (Android).
#
# Зачем: на десктопе GUI запускает внешний процесс (wg_worker) и говорит с ним
# по TCP. На Android так нельзя: OS.execute() в Godot 3 не реализован, а
# Android 10+ запрещает запускать бинарники из каталога приложения. Поэтому
# здесь тот же движок (libvanity_gdnative.so, собранный из mkp224o ed25519-donna)
# вызывается напрямую через GDNative.
#
# Интерфейс намеренно повторяет WorkerBridge.gd — Main.gd не знает, кто именно
# за ним стоит: сигналы connected/message/failed, методы launch/is_alive/
# get_pid/send/shutdown. Форматы сообщений (started/stats/found/stopped/error)
# тоже совпадают с воркером.
#
# ВАЖНО про потоки: C-движок держит состояние в глобальных static-буферах и не
# потокобезопасен, поэтому поиск идёт в ОДНОМ фоновом потоке (workers всегда 1).

signal connected
signal message(msg)      # Dictionary
signal failed(reason)    # String

const CHUNK := 262144
const ONION_CHARS := "abcdefghijklmnopqrstuvwxyz234567"
const B64_CHARS := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
const ONION_SECRET_MAGIC := "== ed25519v1-secret: type0 =="
const ONION_PUBLIC_MAGIC := "== ed25519v1-public: type0 =="

const CHAR_SUBS := {
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
const ONION_SUBS := {
	"a": ["a", "4"], "b": ["b"], "c": ["c"], "d": ["d"], "e": ["e", "3"],
	"f": ["f"], "g": ["g", "6"], "h": ["h"], "i": ["i", "l"], "j": ["j"],
	"k": ["k"], "l": ["l", "i"], "m": ["m"], "n": ["n"], "o": ["o"],
	"p": ["p"], "q": ["q"], "r": ["r"], "s": ["s", "5"], "t": ["t", "7"],
	"u": ["u"], "v": ["v"], "w": ["w"], "x": ["x"], "y": ["y"], "z": ["z", "2"],
	"2": ["2", "z"], "3": ["3", "e"], "4": ["4", "a"], "5": ["5", "s"],
	"6": ["6", "g"], "7": ["7", "t"],
}

var _engine = null
var _thread: Thread = null
var _running := false
var _alive := false
var _pid := 0
var _search_id := 0

# --- интерфейс, совпадающий с WorkerBridge ---------------------------------

func is_alive() -> bool:
	return _alive

func get_pid() -> int:
	return _pid

func launch(_exe: String) -> void:
	# Внешнего процесса нет. Движок грузим ЛЕНИВО (при первом поиске, см.
	# _ensure_engine): если GDNative-библиотека не загрузится или подвиснет,
	# приложение всё равно стартует и показывает интерфейс.
	_alive = true
	_pid = 0
	call_deferred("_emit_ready", "локальный движок (загружается по запросу)")

func shutdown() -> void:
	send({"type": "quit"})

func send(msg: Dictionary) -> void:
	var t = str(msg.get("type", ""))
	match t:
		"start":
			_start(msg)
		"stop":
			_stop()
		"quit":
			_shutdown()

# --- поиск -----------------------------------------------------------------

func _ensure_engine() -> bool:
	if _engine != null:
		return true
	var gdns = load("res://vanity_engine.gdns")
	if gdns == null:
		_emit_failed("не загрузился res://vanity_engine.gdns (GDNative)")
		return false
	_engine = gdns.new()
	if _engine == null:
		_emit_failed("не удалось создать VanityEngine (нет .so под этот ABI?)")
		return false
	return true

func _start(msg: Dictionary) -> void:
	if not _ensure_engine():
		return
	if _running:
		_emit_error("Поиск уже запущен")
		return
	var kind = str(msg.get("kind", "wg"))
	var word = str(msg.get("word", "")).strip_edges()
	var strict = bool(msg.get("strict", false))
	if word == "":
		_emit_error("Слово не может быть пустым")
		return
	var prefixes := []
	if kind == "onion":
		prefixes = _make_prefixes(word.to_lower(), strict, ONION_SUBS, ONION_CHARS)
	else:
		prefixes = _make_prefixes(word, strict, CHAR_SUBS, B64_CHARS)
	if prefixes.size() == 0:
		_emit_error("не удалось построить префиксы")
		return

	var kind_id = 0 if kind == "onion" else 1
	# CSPRNG (mbedTLS): таймерный RNG не годится — два устройства из одного
	# снапшота дали бы одинаковый поиск.
	var crypto = Crypto.new()
	var sd = crypto.generate_random_bytes(48)
	var rc = _engine.init(sd)
	if rc != 0:
		_emit_error("init вернул %d" % rc)
		return
	rc = _engine.set_prefixes(kind_id, prefixes)
	if rc != 0:
		_emit_error("недопустимый префикс (%d)" % rc)
		return

	_search_id = int(msg.get("search_id", 1))
	_running = true
	_emit_message({
		"type": "started", "search_id": _search_id, "word": word,
		"kind": kind, "strict": strict, "workers": 1,
		"prefix_count": prefixes.size(), "engine": "native",
		"substitutions": 0,
	})
	var ctx := {
		"kind": kind, "kind_id": kind_id, "word": word, "strict": strict,
		"prefixes": prefixes, "search_id": _search_id,
		"save": bool(msg.get("save", true)),
		"out_dir": str(msg.get("out_dir", "")),
		"server": msg.get("server", {}),
	}
	_thread = Thread.new()
	_thread.start(self, "_thread_loop", ctx)

func _stop() -> void:
	if not _running:
		return
	_running = false
	_finish_thread()
	_emit_message({"type": "stopped", "search_id": _search_id,
		"checked": 0, "elapsed": 0.0})

func _shutdown() -> void:
	_running = false
	_finish_thread()
	_alive = false
	call_deferred("_emit_message", {"type": "bye"})

func _finish_thread() -> void:
	if _thread != null:
		_thread.wait_to_finish()
		_thread = null

# --- фоновый поток ----------------------------------------------------------

func _thread_loop(ctx: Dictionary) -> void:
	var t0 := OS.get_ticks_msec()
	var checked := 0
	var peak := 0
	var last_stats := t0
	var last_checked := 0
	var found_res = null
	while _running:
		var r = _engine.search(ctx.kind_id, CHUNK)
		var c := int(r.get("checked", 0))
		checked += c
		if bool(r.get("found", false)):
			found_res = r
			break
		if c == 0:
			break
		var now := OS.get_ticks_msec()
		if now - last_stats >= 400:
			var el := float(now - t0) / 1000.0
			var speed := float(checked - last_checked) / max(0.001, float(now - last_stats) / 1000.0)
			if int(speed) > peak:
				peak = int(speed)
			var avg := float(checked) / max(0.001, el)
			var eta = null
			if avg > 0.0 and ctx.prefixes.size() > 0:
				var alphabet := 32 if ctx.kind == "onion" else 64
				var expected := pow(float(alphabet), float(ctx.word.length())) / float(ctx.prefixes.size())
				var remain = max(0.0, expected - float(checked))
				eta = int(remain / avg)
			call_deferred("_emit_message", {
				"type": "stats", "search_id": ctx.search_id,
				"elapsed": round(el * 100.0) / 100.0, "checked": checked,
				"speed": int(speed), "avg": int(avg), "peak": peak, "eta": eta,
			})
			last_stats = now
			last_checked = checked

	_running = false
	var elapsed := float(OS.get_ticks_msec() - t0) / 1000.0
	if found_res == null:
		return
	var files := []
	var qr_b64 := ""
	if ctx.save:
		var res = _save_result(ctx, found_res, elapsed, checked)
		files = res[0]
		qr_b64 = res[1]
	var out := {
		"type": "found", "search_id": ctx.search_id, "kind": ctx.kind,
		"prefix": str(found_res.get("prefix", "")),
		"checked": checked, "elapsed": round(elapsed * 100.0) / 100.0,
		"worker_id": 1, "files": files, "qr_png_b64": qr_b64,
		"engine": "native",
	}
	if ctx.kind == "onion":
		out["onion"] = str(found_res.get("onion", ""))
		out["public_key_b64"] = _b64(found_res.get("pub", PoolByteArray()))
		out["seed_b64"] = _b64(found_res.get("priv", PoolByteArray()))
	else:
		out["public_key"] = _b64(found_res.get("pub", PoolByteArray()))
		out["private_key"] = _b64(found_res.get("priv", PoolByteArray()))
	call_deferred("_emit_message", out)

# --- сохранение результатов -------------------------------------------------

func _out_dir(ctx: Dictionary) -> String:
	var d = str(ctx.get("out_dir", ""))
	if d == "":
		d = OS.get_user_data_dir() + "/out"
	Directory.new().make_dir_recursive(d)
	return d

func _stamp() -> String:
	var t = OS.get_datetime()
	return "%04d%02d%02d_%02d%02d%02d" % [t.year, t.month, t.day, t.hour, t.minute, t.second]

func _write(dpath: String, fname: String, text: String) -> String:
	var f = File.new()
	if f.open(dpath + "/" + fname, File.WRITE) == OK:
		f.store_string(text)
		f.close()
		return fname
	return ""

func _write_bytes(dpath: String, fname: String, data: PoolByteArray) -> String:
	var f = File.new()
	if f.open(dpath + "/" + fname, File.WRITE) == OK:
		f.store_buffer(data)
		f.close()
		return fname
	return ""

func _save_result(ctx: Dictionary, r, elapsed: float, checked: int) -> Array:
	# QR на Android не строится (нет QR-энкодера в GDScript) — GUI просто не
	# покажет картинку, сами ключи сохраняются и копируются.
	var dpath = _out_dir(ctx)
	var prefix = str(r.get("prefix", ""))
	var ts = _stamp()
	var files := []
	if ctx.kind == "onion":
		var onion = str(r.get("onion", ""))
		var svc = dpath + "/" + onion + ".onion"
		Directory.new().make_dir_recursive(svc)
		_write(svc, "hostname", onion + ".onion\n")
		files.append(onion + ".onion/hostname")
		var pub = r.get("pub", PoolByteArray())
		var sec = r.get("priv", PoolByteArray())
		var magic_pub = _with_magic(ONION_PUBLIC_MAGIC)
		magic_pub.append_array(pub)
		_write_bytes(svc, "hs_ed25519_public_key", magic_pub)
		files.append(onion + ".onion/hs_ed25519_public_key")
		var magic_sec = _with_magic(ONION_SECRET_MAGIC)
		magic_sec.append_array(sec)
		_write_bytes(svc, "hs_ed25519_secret_key", magic_sec)
		files.append(onion + ".onion/hs_ed25519_secret_key")
		var txtname = "onion_%s_%s_%s.txt" % [ctx.word, prefix, ts]
		var txt = "Tor onion v3 адрес (vanity) — %s\n" % ctx.word
		txt += "=".repeat(70) + "\n"
		txt += "Адрес: %s.onion\n" % onion
		txt += "Префикс: %s\n" % prefix
		txt += "Проверено ключей: %d\n" % checked
		txt += "Время: %.1f с\n" % elapsed
		txt += "seed (base64):\n%s\n" % _b64(sec)
		txt += "публичный ключ (base64):\n%s\n" % _b64(pub)
		if _write(dpath, txtname, txt) != "":
			files.append(txtname)
		_append_log(dpath, "onion_keys_log.txt", onion + ".onion", ctx, checked, elapsed)
		files.append("onion_keys_log.txt")
	else:
		var priv64 = _b64(r.get("priv", PoolByteArray()))
		var pub64 = _b64(r.get("pub", PoolByteArray()))
		var base = "wg_%s_%s_%s" % [ctx.word, prefix, ts]
		var server = ctx.get("server", {})
		var conf = "[Interface]\n"
		conf += "PrivateKey = %s\n" % priv64
		conf += "Address = %s\n" % str(server.get("client_address", "10.0.0.2/32"))
		conf += "DNS = %s\n" % str(server.get("dns", "1.1.1.1, 8.8.8.8"))
		conf += "\n[Peer]\n"
		conf += "PublicKey = %s\n" % str(server.get("public_key", ""))
		conf += "Endpoint = %s\n" % str(server.get("endpoint", ""))
		conf += "AllowedIPs = %s\n" % str(server.get("allowed_ips", "0.0.0.0/0"))
		conf += "PersistentKeepalive = 25\n"
		if _write(dpath, base + ".conf", conf) != "":
			files.append(base + ".conf")
		var keys = "WireGuard vanity-ключ — %s\n" % ctx.word
		keys += "=".repeat(70) + "\n"
		keys += "Префикс: %s\n" % prefix
		keys += "Приватный ключ: %s\n" % priv64
		keys += "Публичный ключ: %s\n" % pub64
		keys += "Проверено ключей: %d\n" % checked
		keys += "Время: %.1f с\n" % elapsed
		if _write(dpath, base + "_keys.txt", keys) != "":
			files.append(base + "_keys.txt")
		_append_log(dpath, "wg_keys_log.txt", pub64, ctx, checked, elapsed)
		files.append("wg_keys_log.txt")
	return [files, ""]

func _append_log(dpath: String, fname: String, what: String, ctx: Dictionary, checked: int, elapsed: float) -> void:
	var f = File.new()
	var exists = f.file_exists(dpath + "/" + fname)
	if f.open(dpath + "/" + fname, File.READ_WRITE) != OK:
		return
	f.seek_end()
	if not exists:
		f.store_string("=".repeat(80) + "\nЛОГ НАЙДЕННЫХ КЛЮЧЕЙ (Android)\n" + "=".repeat(80) + "\n\n")
	f.store_string("[%s]\n" % _stamp())
	f.store_string("Слово: %s\n" % ctx.word)
	f.store_string("Найдено: %s\n" % what)
	f.store_string("Проверено: %d за %.1f с\n" % [checked, elapsed])
	f.store_string("-".repeat(80) + "\n\n")
	f.close()

# --- вспомогательное --------------------------------------------------------

func _with_magic(s: String) -> PoolByteArray:
	var b := s.to_utf8()
	b.append(0)
	b.append(0)
	b.append(0)
	return b

func _b64(data) -> String:
	if data == null:
		return ""
	return Marshalls.raw_to_base64(data)

func _make_prefixes(word: String, strict: bool, subs: Dictionary, alphabet: String) -> Array:
	var variants := [""]
	for i in range(word.length()):
		var ch = word.substr(i, 1)
		if alphabet.find(ch) == -1:
			return []
		var repls = [ch]
		if not strict and subs.has(ch):
			repls = subs[ch]
		var next := []
		for v in variants:
			for r in repls:
				next.append(v + r)
		variants = next
	return variants

func _emit_message(m: Dictionary) -> void:
	emit_signal("message", m)

func _emit_ready(info: String) -> void:
	emit_signal("connected")
	emit_signal("message", {"type": "ready", "engine": "native", "info": info})

func _emit_failed(reason: String) -> void:
	_alive = false
	emit_signal("failed", reason)

func _emit_error(text: String) -> void:
	_running = false
	emit_signal("message", {"type": "error", "search_id": _search_id, "message": text})
