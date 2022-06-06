#
# Dummy Kerberos authentication schema
#
# Features:
# * AD environment
# * RC4 encryption for tickets
#

"""
Ticket cipher suite:
    AD support DES/RC4/AES128/AES256, defined in LDAP Attribute: msDS-SupportedEncryptionTypes.
    See: https://ldapwiki.com/wiki/Kerberos%20Encryption%20Types
        https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-supportedencryptiontypes,
        https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797:
"""

import pprint
import json
import time

import crypto


def dict2bytes(input_dict: dict) -> bytes:
    return bytes(json.dumps(input_dict), 'utf-8')


def bytes2dict(input_bytes: bytes) -> dict:
    return json.loads(str(input_bytes, 'utf-8'))


def timestamp() -> int:
    return int(time.time())


# Dummy LDAP resources sharing
LDAP_RESOURCES = {
    'users': {
        'user1': {
            'hash': crypto.hash_ntlm('test1234')
        },
        'user2': {
            'hash': crypto.hash_ntlm('serviceOwner')
        }
    },
    'services': {
        'example.net': {
            'http': {
                'owner': 'user2'
            }
        }
    }
}


class KerberosServer:
    """
    Kerberos KDC (Key Distribution Center) with an AS (Authentication Service),
    located on DC (Domain Controller) in AD.
    """

    def __init__(self, domain) -> None:
        """Accounts in LDAP or SAM (Security Account Manager)"""
        self.domain = domain
        self.accounts = {
            **LDAP_RESOURCES['users'],
            **{
                'krbtgt': {
                    'hash': crypto.hash_ntlm('DCpassword')
                }
            }
        }

    def s2_KRB_AS_REP(self, KRB_AS_REQ: dict) -> dict:
        account, domain = KRB_AS_REQ['sname'][0].split('/')
        if KRB_AS_REQ['type'] == 'AS_REQ' and (account == 'krbtgt' and domain == self.domain.upper()):
            user = KRB_AS_REQ['cname']
            ntlm = self.accounts[user]['hash']
            print(f'[kdc] Stored NTLM hash for: {user} is: {ntlm}')

            if crypto.verify(KRB_AS_REQ['timestamp'], ntlm):  # TODO: Validate timestamp interval
                session_key = crypto.random2key()
                print(f'[kdc] Random session key: {[session_key]}')
                rep = {
                    'type': 'AS_REP',
                    'cname': user,
                    'encrypted': crypto.encrypt(
                        dict2bytes({
                            'key': session_key,
                            'endtime': '',
                        }), self.accounts[user]['hash']),
                    'tgt': crypto.encrypt(
                        dict2bytes({
                            'sname': [f'krbtgt/{self.domain.upper()}'],
                            'key': session_key,
                            'endtime': '',
                        }), self.accounts['krbtgt']['hash'])
                }
                print(f'[kdc] Full AS_REP payload:')
                pprint.pprint(rep)
                print('\n')
                return rep
            else:
                print(f'[kdc] Invalid KDC SPN')
                """
                Return Kerberos Error Code
                See: https://ldapwiki.com/wiki/Kerberos%20Error%20Codes
                """

    def s4_KRB_TGS_REP(self, KRB_TGS_REQ: dict) -> dict:
        if KRB_TGS_REQ['type'] == 'TGS_REQ' and crypto.verify(KRB_TGS_REQ['tgt'], self.accounts['krbtgt']['hash']):
            decrypted_tgt = bytes2dict(crypto.decrypt(KRB_TGS_REQ['tgt'], self.accounts['krbtgt']['hash']))
            # TODO: Validate TGT end time
            print(f'[kdc] Received TGT key is: {[decrypted_tgt["key"]]}')
            decrypted = bytes2dict(crypto.decrypt(KRB_TGS_REQ['encrypted'], decrypted_tgt['key']))
            service, domain = KRB_TGS_REQ['sname'][0].split('/')
            service_owner = LDAP_RESOURCES['services'][domain.lower()][service]['owner']
            service_owner_hash = LDAP_RESOURCES['users'][service_owner]['hash']
            service_session_key = crypto.random2key()
            print(f'[kdc] Random service session key: {[service_session_key]}')
            rep = {
                'type': 'TGS_REP',
                'cname': decrypted['cname'],
                'encrypted': crypto.encrypt(
                    dict2bytes({
                        'key': service_session_key,
                        'endtime': ''
                    }), decrypted_tgt['key']),
                'tgs': crypto.encrypt(
                    dict2bytes({
                        'key': service_session_key,
                        'cname': decrypted['cname'],
                        'endtime': ''
                    }), service_owner_hash)
            }
            print(f'[kdc] Full TGS_REP payload:')
            pprint.pprint(rep)
            print('\n')
            return rep
        else:
            print(f'[kdc] Checksum error')
            """
            Return Kerberos Error Code
            See: https://ldapwiki.com/wiki/Kerberos%20Error%20Codes
            """


class Client:
    def __init__(self, domain, target, username) -> None:
        """Accounts in LDAP or SAM (Security Account Manager)"""
        # self.accounts = LDAP_ACCOUNTS['users']
        self.domain = domain
        self.target = target
        self.username = username

    def s1_KRB_AS_REQ(self) -> dict:
        # ntlm = self.accounts['users'][self.username]['hash']
        ntlm = crypto.hash_ntlm(input(f'[client] Username: {self.username}, password: '))
        print(f'[client] Generated NTLM hash for this credentials: {ntlm}')

        raw_timestamp = timestamp()
        encrypted_timestamp = crypto.encrypt(raw_timestamp.to_bytes(4, 'little'), ntlm)
        req = {
            'type': 'AS_REQ',
            'timestamp': encrypted_timestamp,
            'sname': [f'krbtgt/{self.domain.upper()}'],  # Service Principal Name (SPN)
            'cname': self.username,
            'till': ''  # TODO
        }
        print(f'[client] Full AS_REQ payload:')
        pprint.pprint(req)
        print('\n')
        return req

    def s3_KRB_TGS_REQ(self, KRB_AS_REP: dict) -> dict:
        ntlm = LDAP_RESOURCES['users'][KRB_AS_REP['cname']]['hash']  # Self hash
        if KRB_AS_REP['type'] == 'AS_REP' and crypto.verify(KRB_AS_REP['encrypted'], ntlm):
            decrypted = bytes2dict(crypto.decrypt(KRB_AS_REP['encrypted'], ntlm))
            print(f'[client] NTLM hash for cname = user1 is: {ntlm}')
            req = {
                'type': 'TGS_REQ',
                'sname': [self.target],
                'tgt': KRB_AS_REP['tgt'],
                'encrypted': crypto.encrypt(
                    dict2bytes({
                        'cname': KRB_AS_REP['cname'],
                        'timestamp': timestamp(),
                    }), decrypted['key'])
            }

            print(f'[client] Full TGS_REQ payload:')
            pprint.pprint(req)
            print('\n')
            return req
        else:
            print('[client] Checksum error')

    def s5_AP_REQ(self, KRB_AS_REP: dict, KRB_TGS_REP: dict) -> dict:
        if KRB_AS_REP['type'] == 'AS_REP' and KRB_TGS_REP['type'] == 'TGS_REP':
            ntlm = LDAP_RESOURCES['users'][KRB_AS_REP['cname']]['hash']
            decrypted_as_rep = bytes2dict(crypto.decrypt(KRB_AS_REP['encrypted'], ntlm))
            if crypto.verify(KRB_AS_REP['encrypted'], ntlm) and crypto.verify(KRB_TGS_REP['encrypted'], decrypted_as_rep['key']):
                decrypted_tgs_rep = bytes2dict(crypto.decrypt(KRB_TGS_REP['encrypted'], decrypted_as_rep['key']))
                req = {
                    'type': 'AP_REQ',
                    'encrypted': crypto.encrypt(
                        dict2bytes({
                            'cname': KRB_TGS_REP['cname'],
                            'timestamp': timestamp(),
                        }), decrypted_tgs_rep['key']),
                    'tgs': KRB_TGS_REP['tgs']
                }
                print(f'[client] Full AP_REQ payload:')
                pprint.pprint(req)
                print('\n')
                return req


class Service:
    """
    AP (Application Server)
    """
    def __init__(self, owner) -> None:
        self.owner = owner

    def s6_AP_REP(self, AP_REQ: dict) -> None:
        ntml = LDAP_RESOURCES['users'][self.owner]['hash']
        if AP_REQ['type'] == 'AP_REQ' and crypto.verify(AP_REQ['tgs'], ntml): # Self hash
            decrypted_tgs = bytes2dict(crypto.decrypt(AP_REQ['tgs'], ntml))
            print(f'[service] Decrypted TGS:')
            pprint.pprint(decrypted_tgs)
            if crypto.verify(AP_REQ['encrypted'], decrypted_tgs['key']):
                decrypted = bytes2dict(crypto.decrypt(AP_REQ['encrypted'], decrypted_tgs['key']))
