extends SceneTree

func _init() -> void:
	var scene = load("res://main.tscn")
	print("MAIN_SCENE_LOADED ", scene != null)
	if scene == null:
		quit()
		return
	var inst = scene.instance()
	print("MAIN_SCENE_INST ", inst != null, " script=", inst.get_script())
	root.add_child(inst)
	print("ADDED_TO_TREE")
	# проверим флаг из _ready через call_deferred после входа в дерево
	call_deferred("_check")

func _check() -> void:
	var node = root.get_child(root.get_child_count() - 1)
	print("CHILD_OK name=", node.name)
	# найдём _flog-файл — если _ready отработал, он создан
	var f := File.new()
	var logp := "user://gd_log.txt"
	if f.file_exists(logp):
		f.open(logp, File.READ)
		print("GD_LOG_CONTENT>>>")
		print(f.get_as_text())
		f.close()
	else:
		print("GD_LOG_MISSING — _ready не выполнялся")
	quit()
