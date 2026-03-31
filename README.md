### ✨ “泄漏” 与 “检测” 定义
您的 “个人信息” 出现在被 “互联网” 广泛传播的 “部分” 数据中.

### 🚀 “安装” 与 “开发”
```bash
curl -LsSf https://raw.githubusercontent.com/garinasset/leak-check/refs/heads/main/install.sh | bash
```

### 📊 “数据拷贝” 与 “数据库”
本项目不提供 “数据拷贝”. For “数据库”, 您可以采用任何你喜欢的数据库, 本项目采用 “sqlite”.
```bash
cd leak-check

sqlite3 ./db/leak-check.db
```
```sql
-- 
-- 创建表
--
CREATE TABLE source (
    id INTEGER PRIMARY KEY,
    source TEXT DEFAULT NULL
);

CREATE TABLE person(
    id TEXT DEFAULT NULL,
    name TEXT DEFAULT NULL,
    receiver TEXT DEFAULT NULL,
    nickname TEXT DEFAULT NULL,
    phone TEXT DEFAULT NULL,
    address TEXT DEFAULT NULL,
    car TEXT DEFAULT NULL,
    email TEXT DEFAULT NULL,
    qq INTEGER DEFAULT NULL,
    weibo INTEGER DEFAULT NULL,
    contact TEXT DEFAULT NULL,
    company TEXT DEFAULT NULL,
    source_id INTEGER DEFAULT 0,

    FOREIGN KEY (source_id) REFERENCES source(id)
);
```
### 🗑️ 完全卸载

如果需要完全卸载:

```bash
# 删除项目目录即可
rm -rf leak-check/
```

### 📬 更新与反馈
- GitHub 仓库：[https://github.com/garinasset/leak-check](https://github.com/garinasset/leak-check)  
- Issues & Bug 报告：[https://github.com/garinasset/leak-check/issues](https://github.com/garinasset/leak-check/issues)
