# 安装

## 安装方式

将插件目录放置到 AstrBot 的 `data/plugins/` 目录下：

```
data/plugins/astrbot_plugin_matrix_adapter/
```

安装插件后，AstrBot 会自动根据 `requirements.txt` 为插件安装依赖库。

## 依赖安装

AstrBot 插件依赖通过插件目录下的 `requirements.txt` 管理。一般情况下，AstrBot 会在安装好插件后自动为插件安装依赖库；若出现 `No module named 'xxx'` 等报错，可能是网络问题、`requirements.txt` 缺失或 Python 版本不兼容导致依赖未正确安装。此时可在 AstrBot WebUI 的 `控制台` -> `安装 Pip 库` 中手动安装依赖，或在 AstrBot 运行环境中执行：

```
python -m pip install -r data/plugins/astrbot_plugin_matrix_adapter/requirements.txt
```

重启 AstrBot 后，插件会自动加载。