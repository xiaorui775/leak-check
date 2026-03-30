from typing import Annotated, Sequence, Set

from fastapi import Depends
from pydantic import EmailStr
from sqlalchemy import func
from sqlalchemy.orm import selectinload
from sqlmodel import Session, create_engine, select

from models.database import Person

# ---------- 数据库路径 ----------
sqlite_file_name = "leak-check.db"
sqlite_url = f"sqlite:///db/{sqlite_file_name}"

# ---------- 创建 Engine ----------
connect_args = {"check_same_thread": False}  # SQLite 特有
engine = create_engine(sqlite_url, connect_args=connect_args)


# ---------- Session 依赖 ----------
def get_session():
    with Session(engine) as session:
        yield session


# 用于 FastAPI 注入依赖
SessionDep = Annotated[Session, Depends(get_session)]


def read_counts(session: SessionDep) -> str:
    stmt = select(func.max(Person.rowid))
    counts = session.exec(stmt).one()
    return str(counts)


def read_persons_by_dig(
        session: Session,
        *,
        id_: str | None = None,
        phone_: str | None = None,
        email_: str | None = None,
        qq_: int | None = None,
        max_depth: int = 2,  # ✅ 最大挖掘深度
        max_records: int = 64,  # ✅ 最大记录数保护（推荐）
        threshold: int = 8  # ✅ 关键：数据源阈值
) -> Sequence["Person"]:
    """
    深度查询（带深度限制）

    参数说明：
    - max_depth: 最大扩散层数（类似 BFS 层级）
    - max_records: 最大返回记录数，防止数据爆炸
    """

    # 初始化字段集合（当前层）
    id_set: Set[str] = set()
    if id_:
        id_set.add(id_.strip())
        id_set.add(id_.strip().upper())
        id_set.add(id_.strip().lower())

    phone_set: Set[str] = {phone_} if phone_ is not None else set()
    email_set: Set[str] = {email_} if email_ is not None else set()
    qq_set: Set[int] = {qq_} if qq_ is not None else set()

    # 所有已发现记录（去重）
    all_persons: dict[int, "Person"] = {}

    # 当前层计数
    current_depth = 0

    while current_depth < max_depth:
        current_depth += 1

        new_ids, new_phones, new_emails, new_qqs = set(), set(), set(), set()

        results = []

        # ✅ 分字段查询（避免 OR，全走索引）
        # =========================
        # 🚨 id 字段
        # =========================
        if id_set:
            id_results = session.exec(
                select(Person).where(Person.id.in_(id_set))
            ).all()

            if current_depth <= max_depth and len(id_results) > threshold:
                print(f"WARN:     🔥 BFS 处于 {current_depth} 层 [ID字段异常] 命中 {len(id_results)} 条")
                print(f"WARN:     输入值: {list(id_set)}")

            results += id_results

        # =========================
        # 🚨 phone 字段ß
        # =========================
        if phone_set:
            phone_results = session.exec(
                select(Person).where(Person.phone.in_(phone_set))
            ).all()

            if current_depth <= max_depth and len(phone_results) > threshold:
                print(f"WARN:     🔥 BFS 处于 {current_depth} 层 [PHONE字段异常] 命中 {len(phone_results)} 条")
                print(f"WARN:     输入值: {list(phone_set)}")

            results += phone_results

        # =========================
        # 🚨 email 字段
        # =========================
        if email_set:
            email_results = session.exec(
                select(Person).where(Person.email.in_(email_set))
            ).all()

            if current_depth <= max_depth and len(email_results) > threshold:
                print(f"WARN:     🔥 BFS 处于 {current_depth} 层 [EMAIL字段异常] 命中 {len(email_results)} 条")
                print(f"WARN:     输入值: {list(email_set)}")

            results += email_results

        # =========================
        # 🚨 qq 字段
        # =========================
        if qq_set:
            qq_results = session.exec(
                select(Person).where(Person.qq.in_(qq_set))
            ).all()

            if current_depth <= max_depth and len(qq_results) > threshold:
                print(f"WARN:     🔥 BFS 处于 {current_depth} 层 [QQ字段异常] 命中 {len(qq_results)} 条")
                print(f"WARN:     输入值: {list(qq_set)}")

            results += qq_results

        # 记录本轮是否有新增
        has_new_data = False

        for person in results:
            if person.rowid in all_persons:
                continue

            all_persons[person.rowid] = person
            has_new_data = True

            # 收集下一层要用的字段
            if person.id and person.id not in id_set:
                new_ids.add(person.id)
            if person.phone and person.phone not in phone_set:
                new_phones.add(person.phone)
            if person.email and person.email not in email_set:
                new_emails.add(person.email)
            if person.qq and person.qq not in qq_set:
                new_qqs.add(person.qq)

        # ✅ 安全保护：记录数限制
        if len(all_persons) >= max_records:
            print(f"WARN:     BFS 处于 {current_depth} 层, 达到最大记录限制 {max_records}，提前停止")
            break

        # ✅ 没有新数据 → 提前结束（比 max_depth 更早停）
        if not has_new_data:
            break

        # 更新到下一层
        id_set = new_ids
        phone_set = new_phones
        email_set = new_emails
        qq_set = new_qqs

        # （可选）调试日志
        # print(f"深度 {current_depth}，累计 {len(all_persons)} 条")

    return list(all_persons.values())