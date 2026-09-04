extends Node
# WorkerBridge — запуск внешнего вычислителя (wg_worker.exe) и JSON-lines
# общение с ним по локальному TCP. Worker сам выбирает порт и пишет его
# в файл (--portfile); мы ждём файл и подключаемся.

signal connected
signal message(msg)      # Dictionary
signal failed(reason)

enum St { IDLE, LAUNCHING, WAITING_PORT, CONNECTING, CONNECTED, DEAD }

var worker_exe = ""
var state = St.IDLE

var _portfile = ""
var _pidfile = ""
var _secret = ""
var _peer = StreamPeerTCP.new()
var _recv_buf = ""
var _pending = []
var _t_launch = 0.0
var _retry_t = 0.0
var _pid = 0

func _ready() -> void:
	_peer.set_no_delay(true)

func is_alive() -> bool:
	return state == St.CONNECTED or state == St.CONNECTING \
			or state == St.WAITING_PORT or state == St.LAUNCHING

func get_pid() -> int:
	return _pid

func launch(exe: String) -> void:
	worker_exe = exe
	if not File.new().file_exists(exe):
		state = St.DEAD
		emit_signal("failed", "Не найден файл вычислителя: " + exe)
		return
	var tmp = OS.get_user_data_dir() + "/tmp"
	Directory.new().make_dir_recursive(tmp)
	_portfile = tmp + "/wgv_port_%d.txt" % OS.get_unix_time()
	_pidfile = tmp + "/wgv_pid_%d.txt" % OS.get_unix_time()
	_secret = str(randi()) + str(randi())
	var proc_args = ["--portfile", _portfile, "--pidfile", _pidfile, "--secret", _secret]
	# Godot 3: асинхронный запуск отдельного процесса — OS.execute с blocking=false
	var out = []
	var code = OS.execute(exe, proc_args, false, out)
	state = St.LAUNCHING
	_t_launch = OS.get_ticks_msec()

func _process(_delta: float) -> void:
	if state == St.LAUNCHING or state == St.WAITING_PORT:
		if OS.get_ticks_msec() - _t_launch > 20000:
			state = St.DEAD
			emit_signal("failed", "Вычислитель не запустился (нет ответа 20 с)")
			return
		var f = File.new()
		if f.file_exists(_portfile):
			f.open(_portfile, File.READ)
			var txt = f.get_as_text().strip_edges()
			f.close()
			if txt.is_valid_integer():
				var port = int(txt)
				if port > 0:
					state = St.CONNECTING
					_peer.connect_to_host("127.0.0.1", port)
					_retry_t = 0.0
		return
	if state == St.CONNECTING:
		_peer.poll()
		var st = _peer.get_status()
		if st == StreamPeerTCP.STATUS_CONNECTED:
			state = St.CONNECTED
			emit_signal("connected")
			_flush()
			return
		elif st == StreamPeerTCP.STATUS_ERROR:
			# порт мог ещё не открыться — пробуем переподключиться пару раз
			_retry_t += _delta
			if _retry_t > 0.7:
				state = St.WAITING_PORT
				_t_launch = OS.get_ticks_msec()
		return
	if state == St.CONNECTED:
		_peer.poll()
		var avail = _peer.get_available_bytes()
		if avail > 0:
			var err = _peer.get_data(min(avail, 262144))
			if err[0] == OK:
				_recv_buf += err[1].get_string_from_utf8()
				_parse_buf()
		elif _peer.get_status() == StreamPeerTCP.STATUS_ERROR:
			state = St.DEAD
			emit_signal("failed", "Соединение с вычислителем потеряно")

func _parse_buf() -> void:
	while _recv_buf.find("\n") != -1:
		var idx = _recv_buf.find("\n")
		var line = _recv_buf.substr(0, idx).strip_edges()
		_recv_buf = _recv_buf.substr(idx + 1)
		if line.empty():
			continue
		var parsed = JSON.parse(line)
		if parsed.error == OK and parsed.result is Dictionary:
			emit_signal("message", parsed.result)

func _flush() -> void:
	for m in _pending:
		_send_now(m)
	_pending.clear()

func send(msg: Dictionary) -> void:
	if state == St.CONNECTED:
		_send_now(msg)
	else:
		_pending.append(msg)
		if _pending.size() > 64:
			_pending.pop_front()

func _send_now(msg: Dictionary) -> void:
	var line = JSON.print(msg) + "\n"
	_peer.put_data(line.to_utf8())

func shutdown() -> void:
	if state == St.CONNECTED:
		send({"type": "quit"})
		# даём мгновение на graceful quit
		var f = File.new()
		if f.file_exists(_pidfile):
			f.open(_pidfile, File.READ)
			var txt = f.get_as_text().strip_edges()
			f.close()
			if txt.is_valid_integer():
				_pid = int(txt)
		if _pid > 0:
			# дождаться, когда worker завершится сам (до ~1.5 c)
			for i in range(15):
				OS.delay_msec(100)
				if not _proc_alive():
					_pid = 0
					break
			if _pid > 0:
				OS.execute("taskkill.exe", ["/PID", str(_pid), "/F", "/T"], true)
	elif _pid > 0:
		OS.execute("taskkill.exe", ["/PID", str(_pid), "/F", "/T"], true)

func _proc_alive() -> bool:
	var out = []
	var code = OS.execute("tasklist.exe", ["/FI", "PID eq %d" % _pid, "/NH"], true, out)
	if code != 0:
		return true
	var joined = PoolStringArray(out).join(" ")
	return joined.find(str(_pid)) != -1

func _exit_tree() -> void:
	# финальная страховка: если worker ещё жив — убить
	var f = File.new()
	if f.file_exists(_pidfile):
		f.open(_pidfile, File.READ)
		var txt = f.get_as_text().strip_edges()
		f.close()
		if txt.is_valid_integer():
			OS.execute("taskkill.exe", ["/PID", str(txt), "/F", "/T"], true)
