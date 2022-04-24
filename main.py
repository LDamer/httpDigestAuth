from hashlib import md5
from datetime import datetime
import argparse


def compute(d):
    with open(d["wordlist"], "rb") as f:
        start = datetime.now()
        if d["qop"] == "auth":
            m2 = d["method"] + ":" + d["uri"]
            m2 = m2.encode()
            h2 = md5(m2).hexdigest()
            print("start cracking...")
        else:
            print(f"qop={d['qop']} is not supported")
            exit(1)
        while line := f.readline():
            try:
                passwd = line.decode("latin-1").rstrip()
                m1 = (d["username"] + ":" + d["realm"] + ":" + passwd).encode()
                h1 = md5(m1).hexdigest()
            except UnicodeEncodeError:
                print(passwd, " caused an error")
                continue

            #resp_auth_int = "-1"
            resp_auth = "-1"

            if d["qop"] == "auth":
                try:
                    m_qop_auth = (h1 + ":" + d["nonce"] + ":" + d["nc"] + ":" + d["cnonce"] + ":" + d["qop"] + ":" + h2) \
                        .encode()
                    resp_auth = md5(m_qop_auth).hexdigest()
                except UnicodeEncodeError:
                    print(m_qop_auth, " caused an error")
                    continue
            else:
                pass
                #TBD auth-int

            if resp_auth == d["response"]:# or resp_auth_int == d["response"] :
                print("THE PASSWORD IS: ", passwd)
                end = datetime.now()
                print(f"time: {(end - start).total_seconds()}s")
                # print("nc=",nc,",nonce=",n)
                exit(0)

    print("done, nothing found")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("python3 main.py")
    requiredArgs = parser.add_argument_group("required arguments")


    requiredArgs.add_argument("-m", dest="method", type=str, help="Method used for the digest authentication")
    requiredArgs.add_argument("-un", dest="username", type=str, help="username")
    requiredArgs.add_argument("-realm", type=str, help="realm")
    requiredArgs.add_argument("-sn", dest="nonce", type=str, help="server side nonce")
    requiredArgs.add_argument("-cn", dest="cnonce", type=str, help="client side nonce")
    requiredArgs.add_argument("-uri", type=str, help="uri for the digest authentication")
    requiredArgs.add_argument("-res", dest="response", type=str, help="client response to the challenge")
    requiredArgs.add_argument("-qop", type=str, help="quality of protection")
    requiredArgs.add_argument("-nc", type=str, help="server side nonce counter. leading zeroes must be specified!")
    requiredArgs.add_argument("-wl", dest="wordlist", type=str, help="path to wordlist")

    args = parser.parse_args()
    dictionary = vars(args)

    compute(dictionary)
