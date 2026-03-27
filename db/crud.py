from typing import Annotated, Sequence, Set

from fastapi import Depends
from pydantic import EmailStr
from sqlalchemy import func, event
from sqlalchemy.orm import selectinload
from sqlmodel import Session, create_engine, select

from models.database import Person

# ---------- 数据库路径 ----------
sqlite_file_name = "breach.db"
sqlite_url = f"sqlite:///db/{sqlite_file_name}"

# ---------- 创建 Engine ----------
connect_args = {"check_same_thread": False}  # SQLite 特有
engine = create_engine(sqlite_url, connect_args=connect_args)


# ---------- 开启外键约束 ----------
@event.listens_for(engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()

    # 开启外键
    cursor.execute("PRAGMA foreign_keys=ON;")

    # ✅ 验证是否开启成功
    cursor.execute("PRAGMA foreign_keys;")
    cursor.close()


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


"""
查询 单层信息
"""
def read_persons_by_id(
        session: Session,
        id_: str
) -> Sequence[Person]:
    # 查询 身份证号
    persons = session.exec(
        select(Person)
        .options(selectinload(Person.source_obj))
        .where(Person.id == id_)
    ).all()

    return persons

def read_persons_by_phone(
        session: Session,
        phone_: str
) -> Sequence[Person]:
    # 查询 手机号
    persons = session.exec(
        select(Person)
        .options(selectinload(Person.source_obj))
        .where(Person.phone == phone_)
    ).all()

    return persons


def read_persons_by_email(
        session: Session,
        email_: EmailStr
) -> Sequence[Person]:
    # 查询 email
    persons = session.exec(
        select(Person)
        .options(selectinload(Person.source_obj))
        .where(Person.email == email_)
    ).all()

    return persons

def read_persons_by_qq(
        session: Session,
        qq_: int
) -> Sequence[Person]:
    # 查询 QQ号
    persons = session.exec(
        select(Person)
        .options(selectinload(Person.source_obj))
        .where(Person.qq == qq_)
    ).all()

    return persons


def read_persons_by_dig(
        session: Session,
        *,
        id_: str | None = None,
        phone_: str | None = None,
        email_: str | None = None,
        qq_: int | None = None,
        max_depth: int = 2,  # ✅ 最大挖掘深度
        max_records: int = 64  # ✅ 最大记录数保护（推荐）
) -> Sequence["Person"]:
    """
    深度查询（带深度限制 + 性能优化版）

    参数说明：
    - max_depth: 最大扩散层数（类似 BFS 层级）
    - max_records: 最大返回记录数，防止数据爆炸
    """

    # 初始化字段集合（当前层）
    id_set: Set[str] = {id_} if id_ is not None else set()
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
        if id_set:
            results += session.exec(
                select(Person).where(Person.id.in_(id_set))
            ).all()

        if phone_set:
            results += session.exec(
                select(Person).where(Person.phone.in_(phone_set))
            ).all()

        if email_set:
            results += session.exec(
                select(Person).where(Person.email.in_(email_set))
            ).all()

        if qq_set:
            results += session.exec(
                select(Person).where(Person.qq.in_(qq_set))
            ).all()

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
            print(f"[WARN] 达到最大记录限制 {max_records}，提前停止")
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