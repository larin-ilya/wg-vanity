extends SceneTree

func _init() -> void:
	var files := [
		"res://scripts/Style.gd",
		"res://scripts/Toggle.gd",
		"res://scripts/Segmented.gd",
		"res://scripts/RingButton.gd",
		"res://scripts/WorkerBridge.gd",
		"res://scripts/Main.gd",
	]
	for p in files:
		var s = load(p)
		if s == null:
			print("VALIDATE_FAIL ", p)
		else:
			print("VALIDATE_OK   ", p)
	# проверка инстанцирования виджетов
	var t = load("res://scripts/Toggle.gd").new()
	var sg = load("res://scripts/Segmented.gd").new()
	sg.set_options(["A", "B"])
	var rb = load("res://scripts/RingButton.gd").new()
	print("VALIDATE_NEW_OK toggle=", t != null, " seg=", sg != null, " ring=", rb != null)
	quit()
