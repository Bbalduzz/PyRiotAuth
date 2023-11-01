import contextlib
import json
from dataclasses import dataclass
from secrets import token_urlsafe
from time import time
from typing import Callable
from urllib.parse import parse_qs, urlparse

import capmonster_python
import httpx
import jwt
from loguru import logger


def solve_cap_monster(site_url: str, site_key: str, data: str) -> str:
    cap_monster = capmonster_python.HCaptchaTask(
        "<YOUR_API_TOKEN>"
    )  # api key
    cap_monster.set_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36"
    )
    task_id = cap_monster.create_task(
        website_url=site_url,
        website_key=site_key,
        custom_data=data
    )
    result = cap_monster.join_task_result(task_id)
    return result.get("gRecaptchaResponse")


# def solve_2captcha(site_url: str, site_key: str, data: str) -> str:
#     from twocaptcha import TwoCaptcha
#
#     solver = TwoCaptcha("<YOUR_API_TOKEN>")
#     try:
#         result = solver.hcaptcha(
#             sitekey=site_key,
#             url=site_url,
#             param1=data
#         )
#         return json.loads(json.dumps(result))["code"]
#
#     except Exception as e:
#         print(e)


def magic_decode(string: str):
    with contextlib.suppress(json.JSONDecodeError):
        return json.loads(string)
    with contextlib.suppress(jwt.exceptions.DecodeError):
        return jwt.decode(string, options={"verify_signature": False})
    raise ValueError


@dataclass
class User:
    username: str = ""
    password: str = ""

    def __hash__(self):
        return hash(self.username)


@dataclass
class Token:
    access_token: str
    id_token: str
    expire: float
    created = time()


class Version:
    def __init__(self) -> None:
        self.versions = httpx.get(
            "https://valorant-api.com/v1/version"
        ).json()["data"]

    @property
    def riot(self) -> str:
        return self.versions["riotClientBuild"]

    @property
    def sdk(self) -> str:
        return (
            sdk if (sdk := self.versions["riotClientVersion"].split(".")[1])
            else "23.8.0.1382"
        )

    @property
    def valorant(self) -> str:
        return self.versions["riotClientVersion"]


version = Version()


class CaptchaFlow:
    ses: httpx.Client
    user: User

    def __init__(self, solver_fn: Callable[[str, str, str], str]) -> None:
        self.solver_fn = solver_fn

    def get_captcha_token(self) -> dict:
        url = "https://authenticate.riotgames.com/api/v1/login"
        data = {
            "clientId": "riot-client",
            "language": "",
            "platform": "windows",
            "remember": False,
            "riot_identity": {
                "language": "it_IT",
                "state": "auth",
            },
            "sdkVersion": version.sdk,
            "type": "auth",
        }

        return self.ses.post(url, json=data).json()

    def get_login_token(self, code: str) -> str:
        url = "https://authenticate.riotgames.com/api/v1/login"
        data = {
            "riot_identity": {
                "captcha": f"hcaptcha {code}",
                "language": "en_GB",
                "password": self.user.password,
                "remember": False,
                "username": self.user.username
            },
            "type": "auth"
        }
        response_data = self.ses.put(url, json=data).json()
        return response_data["success"]["login_token"]

    def login_cookies(self, login_token: str) -> None:
        url = "https://auth.riotgames.com/api/v1/login-token"
        data = {
            "authentication_type": "RiotAuth",
            "code_verifier": "",
            "login_token": login_token,
            "persist_login": False
        }
        self.ses.post(url, json=data)

    def captcha_flow(self, session: httpx.Client, user: User) -> None:
        self.ses = session
        self.user = user
        captcha_data = self.get_captcha_token()
        captcha_token = self.solver_fn(
            "https://auth.riotgames.com",
            captcha_data["captcha"]["hcaptcha"]["key"],
            captcha_data["captcha"]["hcaptcha"]["data"]
        )
        login_token = self.get_login_token(captcha_token)
        self.login_cookies(login_token)


class RiotAuth:
    __ua = f"RiotClient/{version.riot} %s (Windows;10;;Professional, x64)"

    def __init__(self, user: User, captcha: CaptchaFlow) -> None:
        self.session = httpx.Client(
            headers={
                "User-Agent": self.__ua % "rso-auth",
                "Cache-Control": "no-cache",
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            cookies={"tdid": "", "asid": "", "did": "", "clid": ""}
        )
        logger.debug("Setup authentication")
        self.setup_auth()
        logger.debug("Start captcha solving")
        captcha.captcha_flow(self.session, user)
        logger.debug("Get Token and cookies")
        self.token, self.cookies = self.get_auth_data()
        logger.debug("Get entitlements")
        self.entitlements_token = self.get_entitlement()

    def setup_auth(self) -> httpx.Response:
        url = "https://auth.riotgames.com/api/v1/authorization"
        data = {
            "client_id": "riot-client",
            "nonce": token_urlsafe(16),
            "redirect_uri": "http://localhost/redirect",
            "response_type": "token id_token",
            "scope": "account openid",
        }

        return self.session.post(url, json=data)

    def get_auth_data(self) -> tuple[Token, dict]:
        r = self.setup_auth()
        if "error" in (data := r.json()):
            raise Exception(data["error"])

        return self.get_token(
            data["response"]["parameters"]["uri"]
        ), dict(r.cookies)

    @staticmethod
    def get_token(uri: str) -> Token:
        query_data = parse_qs(urlparse(uri).fragment)

        return Token(
            access_token=query_data["access_token"][0],
            id_token=query_data["id_token"][0],
            expire=time() + float(query_data["expires_in"][0])
        )

    def get_entitlement(self) -> str:
        url = "https://entitlements.auth.riotgames.com/api/token/v1"
        headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Authorization": f"Bearer {self.token.access_token}",
            "User-Agent": self.__ua % "entitlements",
        }
        r = self.session.post(url, headers=headers, json={})

        return magic_decode(r.text)["entitlements_token"]


def get_user_info(session: httpx.Client, token: Token) -> str:
    headers = {
        "Accept-Encoding": "gzip, deflate, br",
        "Authorization": f"Bearer {token.access_token}",
    }
    r = session.post(
        "https://auth.riotgames.com/userinfo", headers=headers, json={}
    )
    return magic_decode(r.text)


def login_and_get_cookies(login: str, password: str) -> dict:
    riot_obj = RiotAuth(
        user=User(login, password),
        captcha=CaptchaFlow(solve_cap_monster)
    )
    return riot_obj.cookies


if __name__ == "__main__":
    # for c in login_and_get_cookies("uesrname", "password").jar:
    #     print(c.name, c.value)
    riot_user = User("uesrname", "password")
    riot_captcha = CaptchaFlow(solve_cap_monster)
    client = RiotAuth(riot_user, riot_captcha)
    print(client.cookies)
    # riot_user = get_user_info(client.session, client.token)
    # print(riot_user)
