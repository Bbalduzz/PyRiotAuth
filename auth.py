import contextlib
from secrets import token_urlsafe
from httpx import Client
import requests
from dataclasses import dataclass
from time import time
import jwt
import capmonster_python
import json

def magic_decode(string: str):
    with contextlib.suppress(json.JSONDecodeError):
        return json.loads(string)
    with contextlib.suppress(jwt.exceptions.DecodeError):
        return jwt.decode(string, options={"verify_signature": False})
    raise DecodeException

@dataclass
class User:
    username: str = ''
    password: str = ''
    def __hash__(self):
        return hash(self.username)

@dataclass
class Token():
    access_token: str
    id_token: str
    expire: float
    created = time()

class Version:
    def __init__(self):
        self.versions = requests.get("https://valorant-api.com/v1/version").json()["data"]
        self.valorant = self.valorant()
        self.riot = self.riot()
        self.sdk = self.sdk()

    def riot(self):
        return self.versions["riotClientBuild"]
    def sdk(self):
        return sdk if (sdk := self.versions["riotClientVersion"].split(".")[1]) else "23.8.0.1382"
    def valorant(self):
        return self.versions["riotClientVersion"]

version = Version()

class CaptchaFlow:
    def __init__(self, session, user):
        self.ses = session
        self.user = user

    def get_captcha_token(self):
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
        url = "https://authenticate.riotgames.com/api/v1/login"
        response_data = self.ses.post(url, json=data).json()
        return response_data

    def get_login_token(self, code: str):
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
        url = "https://authenticate.riotgames.com/api/v1/login"
        response_data = self.ses.put(url, json=data).json()
        return response_data["success"]["login_token"]

    def login_cookies(self, login_token: str):
        data = {
            "authentication_type": "RiotAuth",
            "code_verifier": "",
            "login_token": login_token,
            "persist_login": False
        }
        url = "https://auth.riotgames.com/api/v1/login-token"
        self.ses.post(url, json=data)

    def solve_2captcha(self, data):
        from twocaptcha import TwoCaptcha
        sitekey = data["captcha"]["hcaptcha"]["key"]
        rqdata = data["captcha"]["hcaptcha"]["data"]
        solver = TwoCaptcha("8238186e93d681302e1390b4874a6ed1")
        try:
            result = solver.hcaptcha(
               sitekey=sitekey,
               url='https://auth.riotgames.com/',
               param1=rqdata
            )
            return json.loads(json.dumps(result))["code"]

        except Exception as e:
           print(e)

    def solve_captcha(self, data):
        sitekey = data["captcha"]["hcaptcha"]["key"]
        rqdata = data["captcha"]["hcaptcha"]["data"]
        capmonster = capmonster_python.HCaptchaTask("<YOUR_API_TOKEN>") # api key
        capmonster.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36")
        task_id = capmonster.create_task(website_url="https://auth.riotgames.com", website_key=sitekey, custom_data=rqdata)
        result = capmonster.join_task_result(task_id)
        return result.get("gRecaptchaResponse")

    def captcha_flow(self):
        captcha_data = self.get_captcha_token()
        captcha_token = self.solve_captcha(captcha_data)
        login_token = self.get_login_token(captcha_token)
        self.login_cookies(login_token)

class RiotAuth:
    def __init__(self, user):
        self.session = self.setup_session()
        self.setup_auth(self.session)
        CaptchaFlow(self.session, user).captcha_flow()
        self.token, self.cookies = self.get_auth_data(self.session)
        self.entitlements_token = self.get_entitlement(self.session, self.token)

    def setup_session(self):
        app = "rso-auth"
        session = Client()
        session.headers.update({
            "User-Agent": f'RiotClient/{version.riot} {app} (Windows;10;;Professional, x64)',
            "Cache-Control": "no-cache",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        session.cookies.update({"tdid": "", "asid": "", "did": "", "clid": ""})
        return session

    def setup_auth(self, session):
        data = {
            "client_id": "riot-client",
            "nonce": token_urlsafe(16),
            "redirect_uri": "http://localhost/redirect",
            "response_type": "token id_token",
            "scope": "account openid",
        }

        url = "https://auth.riotgames.com/api/v1/authorization"
        r = session.post(url, json=data)
        return r

    def get_auth_data(self, session):
        r = self.setup_auth(session)
        cookies = dict(r.cookies)
        data = r.json()
        if "error" in data: raise Exception(data["error"])
        uri = data["response"]["parameters"]["uri"]
        token = self.get_token(uri)
        return token, cookies

    def get_token(self, uri: str) -> Token:
        access_token = uri.split("access_token=")[1].split("&scope")[0]
        token_id = uri.split("id_token=")[1].split("&")[0]
        expires_in = uri.split("expires_in=")[1].split("&")[0]
        timestamp = time() + float(expires_in)
        token = Token(access_token, token_id, timestamp)
        return token

    def get_entitlement(self, session, token: Token) -> str:
        app = 'entitlements'
        url = "https://entitlements.auth.riotgames.com/api/token/v1"
        headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Authorization": f"Bearer {token.access_token}",
            "User-Agent": f'RiotClient/{version.riot} {app} (Windows;10;;Professional, x64)',
        }
        r = session.post(url, headers=headers, json={})
        data = magic_decode(r.text)
        return data["entitlements_token"]

def get_user_info(session, token: Token) -> str:
    headers = {
        "Accept-Encoding": "gzip, deflate, br",
        "Authorization": f"Bearer {token.access_token}",
    }
    r = session.post("https://auth.riotgames.com/userinfo", headers=headers, json={})
    return magic_decode(r.text)


if __name__ == "__main__":
    user = User("username", "password")
    client = RiotAuth(user)
    user = get_user_info(client.session, client.token)
    print(user)
