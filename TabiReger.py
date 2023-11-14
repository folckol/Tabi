import base64
import datetime
import json
import random
import re
import ssl
import imaplib
import email
import time
import traceback
from TwitterModel import *

import capmonster_python
import requests
import cloudscraper
from eth_account.messages import encode_defunct
from web3.auto import w3

def random_user_agent():
    browser_list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{2}_{3}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{1}.{2}) Gecko/20100101 Firefox/{1}.{2}',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Edge/{3}.{4}.{5}'
    ]

    chrome_version = random.randint(70, 108)
    firefox_version = random.randint(70, 108)
    safari_version = random.randint(605, 610)
    edge_version = random.randint(15, 99)

    chrome_build = random.randint(1000, 9999)
    firefox_build = random.randint(1, 100)
    safari_build = random.randint(1, 50)
    edge_build = random.randint(1000, 9999)

    browser_choice = random.choice(browser_list)
    user_agent = browser_choice.format(chrome_version, firefox_version, safari_version, edge_version, chrome_build, firefox_build, safari_build, edge_build)

    return user_agent

def get_last_mail(login, password):
    count = 0
    while count < 5:

        # Введите свои данные учетной записи
        email_user = login
        email_pass = password

        if '@rambler' in login or '@lenta' in login or '@autorambler' in login or '@ro' in login:
            # Подключение к серверу IMAP
            mail = imaplib.IMAP4_SSL("imap.rambler.ru")

        else:
            mail = imaplib.IMAP4_SSL("imap.mail.ru")

        mail.login(email_user, email_pass)

        # Выбор почтового ящика
        mail.select("inbox")

        # Поиск писем с определенной темой
        typ, msgnums = mail.search(None, 'SUBJECT "Trove Email Verification"')
        msgnums = msgnums[0].split()

        # Обработка писем
        link = ''

        for num in msgnums:
            typ, data = mail.fetch(num, "(BODY[TEXT])")
            msg = email.message_from_bytes(data[0][1])
            text = msg.get_payload(decode=True).decode()

            # print(text.replace('=\r\n', '').split('<a href=3D"')[1].split('" target=3D"')[0])

            # Поиск ссылки в тексте письма
            link_pattern = r'https://trove-api.treasure.lol/account/verify-email\S*'
            match = re.search(link_pattern, text.replace('=\r\n', '').replace('"', ' '))

            # ('\n\printn')
            if match:
                link = match.group().replace("verify-email?token=3D", "verify-email?token=").replace("&email=3D", "&email=").replace("&redirectUrl=3D", "&redirectUrl=")
                # print(f"Найдена ссылка: \n\n{link}")
            else:
                # print("Ссылка не найдена")
                count += 1
                time.sleep(2)

        # Завершение сессии и выход
        mail.close()
        mail.logout()

        if link != '':
            return link

    return None

class Discord:

    def __init__(self, token, proxy, cap_key):

        self.cap = capmonster_python.HCaptchaTask(cap_key)
        self.token = token
        self.proxy = proxy

        # print(token)
        # print(proxy)
        # print(cap_key)

        self.session = self._make_scraper()
        self.ua = random_user_agent()
        self.session.user_agent = self.ua
        self.session.proxies = self.proxy
        self.super_properties = self.build_xsp(self.ua)


        self.cfruid, self.dcfduid, self.sdcfduid = self.fetch_cookies(self.ua)
        self.fingerprint = self.get_fingerprint()


    def JoinServer(self, invite):

        rer = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token})

        # print(rer.text, rer.status_code)
        # print(rer.text)
        # print(rer.status_code)

        if "200" not in str(rer):
            site = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
            tt = self.cap.create_task("https://discord.com/api/v9/invites/" + invite, site)
            # print(f"Created Captcha Task {tt}")
            captcha = self.cap.join_task_result(tt)
            captcha = captcha["gRecaptchaResponse"]
            # print(f"[+] Solved Captcha ")
            # print(rer.text)

            self.session.headers = {'Host': 'discord.com', 'Connection': 'keep-alive',
                               'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                               'X-Super-Properties': self.super_properties,
                               'Accept-Language': 'en-US', 'sec-ch-ua-mobile': '?0',
                               "User-Agent": self.ua,
                               'Content-Type': 'application/json', 'Authorization': 'undefined', 'Accept': '*/*',
                               'Origin': 'https://discord.com', 'Sec-Fetch-Site': 'same-origin',
                               'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
                               'Referer': 'https://discord.com/@me', 'X-Debug-Options': 'bugReporterEnabled',
                               'Accept-Encoding': 'gzip, deflate, br',
                               'x-fingerprint': self.fingerprint,
                               'Cookie': f'__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; __cf_bm=DFyh.5fqTsl1JGyPo1ZFMdVTupwgqC18groNZfskp4Y-1672630835-0-Aci0Zz919JihARnJlA6o9q4m5rYoulDy/8BGsdwEUE843qD8gAm4OJsbBD5KKKLTRHhpV0QZybU0MrBBtEx369QIGGjwAEOHg0cLguk2EBkWM0YSTOqE63UXBiP0xqHGmRQ5uJ7hs8TO1Ylj2QlGscA='}
            rej = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}, json={
                "captcha_key": captcha,
                "captcha_rqtoken": str(rer.json()["captcha_rqtoken"])
            })
            # print(rej.text())
            # print(rej.status_code)
            if "200" in str(rej):
                return 'Successfully Join 0', self.super_properties
            if "200" not in str(rej):
                return 'Failed Join'

        else:
            with self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}) as response:
                # print(response.text)
                pass
            return 'Successfully Join 1', self.super_properties


    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

    def build_xsp(self, ua):
        # ua = get_useragent()
        _,fv = self.get_version(ua)
        data = json.dumps({
            "os": "Windows",
            "browser": "Chrome",
            "device": "",
            "system_locale": "en-US",
            "browser_user_agent": ua,
            "browser_version": fv,
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": self.get_buildnumber(),
            "client_event_source": None
        }, separators=(",",":"))
        return base64.b64encode(data.encode()).decode()

    def get_version(self, user_agent):  # Just splits user agent
        chrome_version = user_agent.split("/")[3].split(".")[0]
        full_chrome_version = user_agent.split("/")[3].split(" ")[0]
        return chrome_version, full_chrome_version

    def get_buildnumber(self):  # Todo: make it permanently work
        r = requests.get('https://discord.com/app', headers={'User-Agent': 'Mozilla/5.0'})
        asset = re.findall(r'([a-zA-z0-9]+)\.js', r.text)[-2]
        assetFileRequest = requests.get(f'https://discord.com/assets/{asset}.js',
                                        headers={'User-Agent': 'Mozilla/5.0'}).text
        try:
            build_info_regex = re.compile('buildNumber:"[0-9]+"')
            build_info_strings = build_info_regex.findall(assetFileRequest)[0].replace(' ', '').split(',')
        except:
            # print("[-]: Failed to get build number")
            pass
        dbm = build_info_strings[0].split(':')[-1]
        return int(dbm.replace('"', ""))

    def fetch_cookies(self, ua):
        try:
            url = 'https://discord.com/'
            headers = {'user-agent': ua}
            response = self.session.get(url, headers=headers, proxies=self.proxy)
            cookies = response.cookies.get_dict()
            cfruid = cookies.get("__cfruid")
            dcfduid = cookies.get("__dcfduid")
            sdcfduid = cookies.get("__sdcfduid")
            return cfruid, dcfduid, sdcfduid
        except:
            # print(response.text)
            return 1

    def get_fingerprint(self):
        try:
            fingerprint = self.session.get('https://discord.com/api/v9/experiments', proxies=self.proxy).json()['fingerprint']
            # print(f"[=]: Fetched Fingerprint ({fingerprint[:15]}...)")
            return fingerprint
        except Exception as err:
            # print(err)
            return 1



def register_f(web3, address, private_key, params, authority_signature, id):
    my_address = address
    nonce = web3.eth.get_transaction_count(w3.to_checksum_address(my_address))
    who_swap = w3.to_checksum_address(my_address)

    with open('abi.json') as f:
        abi = json.load(f)

    contract = web3.eth.contract(w3.to_checksum_address('0x072b65f891b1a389539e921bdb9427af41a7b1f7'), abi=abi)

    register = contract.get_function_by_selector("0x95f38e77")
    # print(params)
    params = {
        'name': params[0],
        'discriminant': params[1],
        'owner': who_swap,
        'resolver': w3.to_checksum_address(params[2]),
        'nonce': int(params[3], 16),
    }


    transaction = register(params, authority_signature).build_transaction(
        {
            "chainId": web3.eth.chain_id,
            "gasPrice": web3.eth.gas_price,
            "from": who_swap,
            "value": 0,
            "nonce": nonce,
        }
    )

    signed_txn = web3.eth.account.sign_transaction(
        transaction, private_key=private_key
    )

    raw_tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    # print(f'{id} - Transaction signed')
    return web3.to_hex(raw_tx_hash)


class TabiAccount:

    def __init__(self, accs_data, cap_key, id):

        self.id = id
        self.cap_key = cap_key
        self.address = accs_data['address'].lower()
        self.private_key = accs_data['private_key']
        self.tw_auth_token = accs_data['tw_auth_token']
        self.tw_csrf = accs_data['tw_csrf']
        self.discord_token = accs_data['discord_token']
        # self.mail = accs_data['mail']
        # self.mail_pass = accs_data['mail_pass']

        self.defaultFormatProxy = f"{accs_data['proxy'].split('/')[-1].split('@')[1].split(':')[0]}:{accs_data['proxy'].split('/')[-1].split('@')[1].split(':')[1]}:{accs_data['proxy'].split('/')[-1].split('@')[0].split(':')[0]}:{accs_data['proxy'].split('/')[-1].split('@')[0].split(':')[1]}"

        self.proxy = {'http': accs_data['proxy'], 'https': accs_data['proxy']}
        self.static_sitekey = '6LeVGhkkAAAAAIHfvKTSepWAwYiccTiLvGuDXG_V'

        self.session = self._make_scraper()
        adapter = requests.adapters.HTTPAdapter(max_retries=10)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.proxies = self.proxy
        self.session.user_agent = random_user_agent()

    def execute_task(self):
        self.Authorization()
        self.session.headers.update({'Authorization': f'Bearer {self.token}'})
        print('Зашел в акк')

        self.session.get('https://api.tabi.lol/v3/oauth/login?type=2&platform=2')
        self.Connect_Discord()
        print('Подключил ДС')
        input(11)

        Discord(self.discord_token, self.session.proxies, self.cap_key).JoinServer('tabinft')
        print('Зашел в канал')

        self.Connect_Twitter()
        print('Подключил твиттер')

        with self.session.post('https://api.tabi.lol/v3/landingTL/checkBasicTask', json={"task_id":1}, timeout=15) as response:
            # print(response.text)
            pass

        invite = self.session.get('https://api.tabi.lol/v3/landingTL/getInviteCode').json()['data']['userInviteCode']

        TwitterAcc = Account(auth_token=self.tw_auth_token,csrf=self.tw_csrf,proxy=self.defaultFormatProxy,name='1')
        TwitterAcc.Tweet(f"Ahoy, degens! I just discovered a mysterious artifact on @Tabi_NFT.\nJoin me on the voyagers‘ expedition, where we uncover a wealth of exquisite treasures. Hop on board and let's catch the wind. https://tabi.lol?code={invite} ")
        print('Твит сделан')

        time.sleep(7)

        with self.session.post('https://api.tabi.lol/v3/landingTL/checkBasicTask', json={"task_id":3}, timeout=15) as response:
            print(response.text)


    def Authorization(self):
        timestamp = str(datetime.datetime.now().timestamp()).split(".")[0]

        message = encode_defunct(text=self._get_message_to_sign(timestamp))
        signed_message = w3.eth.account.sign_message(message, private_key=self.private_key)
        self.signature = signed_message["signature"].hex()

        payload = {"wallet_address":self.address,
                   "signature":self.signature,
                   "chain_id":56,
                   "timestamp":int(timestamp)}

        with self.session.post('https://api.tabi.lol/v3/login', json=payload, timeout=15) as response:
            self.token = response.json()['data']['access_token']

    def Connect_Discord(self):

        discord_headers = {
            'authority': 'discord.com',
            'authorization': self.discord_token,
            'content-type': 'application/json',
            'x-super-properties': 'eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJydS1SVSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMDkuMC4wLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwOS4wLjAuMCIsIm9zX3ZlcnNpb24iOiIxMC4xNS43IiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjE3NDA1MSwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiZGVzaWduX2lkIjowfQ==',
        }

        payload = {"permissions":"0","authorize":True}

        with self.session.post(f'https://discord.com/api/oauth2/authorize?client_id=1091637762114990110&response_type=code&redirect_uri=https%3A%2F%2Ftabi.lol%2Foauth%2Fcallback&scope=identify%20guilds%20guilds.members.read', json=payload, timeout=15, headers=discord_headers) as response:

            url = response.json()['location']
            print(url)
            self.code = url.split('code=')[-1]

            with self.session.get(url, timeout=15) as response:
                # print(response.text)
                pass

    def Connect_Twitter(self):

        with self.session.get('https://api.tabi.lol/v3/oauth/login?type=1&platform=2', timeout=15, allow_redirects=False) as response:

            url = response.json()['data']['url']

            print(url)

            state = url.split('state=')[-1].split('&')[0]
            code_challenge = url.split('code_challenge=')[-1].split('&')[0]
            client_id = url.split('client_id=')[-1].split('&')[0]

            self.session.cookies.update({'auth_token': self.tw_auth_token, 'ct0': self.tw_csrf})

            # print(self.tw_auth_token, self.tw_csrf)


            with self.session.get(url, timeout=10, allow_redirects=False) as response:

                print(response.text)

                # with self.session.get('https://api.twitter.com/graphql/lFi3xnx0auUUnyG4YwpCNw/GetUserClaims?variables=%7B%7D', timeout=15) as response:
                #     pass
                '9zk9HZ9_EuZex9koIE-hNLTHQ2w'
                twitter_headers = {'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                                   'x-twitter-auth-type': 'OAuth2Session',
                                   'x-csrf-token': self.tw_csrf}
                self.session.cookies.update({'auth_token': self.tw_auth_token, 'ct0': self.tw_csrf})
                time.sleep(1)

                with self.session.get(f'https://twitter.com/i/api/2/oauth2/authorize?code_challenge={code_challenge}&code_challenge_method=plain&client_id={client_id}&redirect_uri=https%3A%2F%2Ftabi.lol%2Foauth%2Fcallback&response_type=code&scope=tweet.read%20users.read%20follows.read%20offline.access%20like.read&state={state}', headers=twitter_headers, timeout=15, allow_redirects=True) as response:
                    print(response.text)
                    code = response.json()['auth_code']

                    payload = {'approval':'true',
                               'code': code}

                    self.session.headers.update({'content-type':'application/x-www-form-urlencoded'})
                    time.sleep(1)
                    with self.session.post('https://twitter.com/i/api/2/oauth2/authorize', headers=twitter_headers, data=payload, timeout=15) as response:
                        time.sleep(1)
                        print(response.text)
                        url = response.json()['redirect_uri']

                        with self.session.get(url, timeout=15) as response:
                            # print(response.text)
                            # print(f'{self.id} - Twitter connected')
                            pass

    def _get_message_to_sign(self, timestamp):

        return 'Hi! Welcome to Tabi.\n\n'\
               'Please sign the message to let us know that you own the wallet.\n\n'\
                'Signing is gas-less and will not give Tabi permission to conduct any transactions with your wallet.\n\n'\
               f'Time stamp is {timestamp}.'

    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )


if __name__ == '__main__':

    TabiAccount({'address': '',
                 'private_key': '',
                 'tw_auth_token': '',
                 'tw_csrf': '',
                 'discord_token': '',
                 'proxy': ''},
                 '',
                 '1').execute_task()


    # print(datetime.datetime.utcnow().timestamp())
