#!/bin/bash
set -e  # 任意一步失败就退出

# 确保 ~/.local/bin 在 PATH 中（uv 会装在这里）
export PATH="$HOME/.local/bin:$PATH"

echo "正在检测 uv（Python 包管理工具) 环境"
if command -v uv >/dev/null 2>&1; then
    echo "uv 已安装."
else
    echo "未检测到 uv，正在使用官方脚本进行安装"
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi

echo "正在获取项目代码"
git clone https://github.com/garinasset/leak-check.git
cd leak-check

echo "正在引入示例数据库"
cp ./example.db ./db/leak-check.db

echo "正在安装 Python 3.14"
uv python install 3.14
uv python list

echo "正在创建虚拟环境"
uv venv

echo "正在安装项目依赖（基于锁文件）"
uv sync --frozen

echo "开发环境部署完成"
echo ""
echo "启动服务："
echo "cd leak-check"
echo "uv run uvicorn main:app --host 0.0.0.0 --port 8000"