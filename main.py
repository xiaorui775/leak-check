import re
from typing import Sequence

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse

from db import crud
from db.crud import SessionDep
from models.database import Person
from models.request import ModelRequestQuery
from models.response import ModelResponsePersonAggregated, ModelResponsePersonAggregatedMasking

from lib.aggregation import clean_str_set, clean_int_set, clean_id_set
from lib.masking import mask_list

app = FastAPI(
    root_path="/leak-check",
    title="172.16.1.4",
    version="1.2.0",
    summary="个人信息 “泄漏” 查询接口",
    contact={
        "name": "嘉林数据",
        "url": "https://leak-check.garinasset.com",
        "email": "contact@garinasset.com",
    },
    license_info={
        "name": "CC BY 4.0",
        "identifier": "CC-BY-4.0",
    }
)

# 允许跨域
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("", summary="Hello leak-check! 🚀 http://172.16.1.4/leak-check",
         response_class=PlainTextResponse,
         responses={
             200: {
                 "content": {
                     "text/plain": {
                         "example": "Hello leak-check!\n"
                     }
                 }
             }
         }
         )
async def root():
    return f"Hello leak-check!\n"


@app.get("/", summary="响应 数据库 记录",
         response_class=PlainTextResponse,
         responses={
             200: {
                 "content": {
                     "text/plain": {
                         "example": "0\n"
                     }
                 }
             }
         }
         )
async def get_counts(session: SessionDep):
    counts = crud.read_counts(session=session)
    return counts


# ---------- 类型识别函数 ----------
def detect_input_type(user_input: str) -> str:
    """
    返回唯一类型：
    - phone
    - qq
    - email
    - id
    - unknown
    """

    phone_pattern = r"^1\d{10}$"
    # 排除手机号的 QQ
    qq_pattern = r"^(?!1\d{10}$)\d{5,11}$"
    email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    id_pattern = r"^\d{17}[\dXx]$"

    if re.fullmatch(phone_pattern, user_input):
        return "phone"
    elif re.fullmatch(email_pattern, user_input):
        return "email"
    elif re.fullmatch(id_pattern, user_input):
        return "id"
    elif re.fullmatch(qq_pattern, user_input):
        return "qq"
    else:
        return "unknown"


@app.post(
    "/dig/masking",
    summary="查询 个人信息“泄漏” 记录 - 脱敏",
    response_model=ModelResponsePersonAggregatedMasking
)
def get_person_by_dig(body: ModelRequestQuery, session: SessionDep):
    # ========================
    # 1. 查询数据
    # ========================
    persons: Sequence[Person] = []

    input_type = detect_input_type(body.q)

    match input_type:
        case "phone":
            persons = crud.read_persons_by_dig(session, phone_=body.q)

        case "qq":
            persons = crud.read_persons_by_dig(session, qq_=int(body.q))

        case "email":
            persons = crud.read_persons_by_dig(session, email_=body.q)

        case "id":
            persons = crud.read_persons_by_dig(session, id_=body.q.upper())

        case _:
            raise ValueError(f"未知类型: {body.q}")

    # ========================
    # 2. 脱敏聚合（核心）
    # ========================
    aggregated = ModelResponsePersonAggregatedMasking(
        # 身份证（必须脱敏）
        id=mask_list("id", (p.id for p in persons)),

        # ===== 基础信息 =====
        name=mask_list("name", (p.name for p in persons)),
        receiver=mask_list("receiver", (p.receiver for p in persons)),
        nickname=mask_list("nickname", (p.nickname for p in persons)),

        # ===== 联系方式 =====
        phone=mask_list("phone", (p.phone for p in persons)),
        email=mask_list("email", (p.email for p in persons)),

        # ===== 数字账号 =====
        qq=mask_list("qq", (p.qq for p in persons)),
        weibo=mask_list("weibo", (p.weibo for p in persons)),

        # ===== 其他信息 =====
        address=mask_list("address", (p.address for p in persons)),
        car=mask_list("car", (p.car for p in persons)),
        contact=mask_list("contact", (p.contact for p in persons)),
        company=mask_list("company", (p.company for p in persons)),

        # ===== 来源（不脱敏）=====
        source=list({
            p.source_obj.source
            for p in persons
            if p.source_obj and p.source_obj.source
        })
    )

    return aggregated
