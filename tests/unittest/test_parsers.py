# Copyright 2019 James Brown
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# flake8: noqa: E501

import pytest

from torpy.parsers import HSDescriptorParser, IntroPointParser, RouterDescriptorParser


@pytest.fixture
def hs_example():
    return """rendezvous-service-descriptor aj7trvc2tuggkzsffrbla3qogs2plltf
version 2
permanent-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALdj5MFZtlrjI54ousrBzA3fSyfn0NC32OBhl61BLgO67vPBiIiFFzo9
YIqa4h3jZQrxdI3MeK4xTLQ6HhnQXvcM+ZR57o5zTR7fpqra89i75rwUjW5wqc9O
3roxzt1UWbJBtbzOT9FYxGSIczsYdG6MQRg9BK/2v391Oz9NbDb1AgMBAAE=
-----END RSA PUBLIC KEY-----
secret-id-part jrhhuswdnmpplrlflxc4buquuzijljkr
publication-time 2019-03-20 06:00:00
protocol-versions 2,3
introduction-points
-----BEGIN MESSAGE-----
aW50cm9kdWN0aW9uLXBvaW50IGt4eGlxenU2YnI0cGg1ZmgybzN1eHh3ZnNjaGpy
a282CmlwLWFkZHJlc3MgMjE3LjIzLjcuMTAzCm9uaW9uLXBvcnQgOTAwMQpvbmlv
bi1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU9E
dG9TajZreUh6WHN4enhwVDgvOGFpV2hCcmVMdGFMbjZybGJhRjUwRnVQWkY5azVG
ZGhnMDAKNjFWbHc1djUzVHlWTFJST042Mkt5TlJZT1o5NWd1V2FEajBDVDBMbCtE
Qzh5OU5ORk83Zk02SG1hR1pkYTlnYwpxYkRtK2JET1JTSHVmd2FzWTNSVHlEVW5H
TWFpSXpxeDJna0l4dEI1TituTkk4eERDVFlEQWdNQkFBRT0KLS0tLS1FTkQgUlNB
IFBVQkxJQyBLRVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJM
SUMgS0VZLS0tLS0KTUlHSkFvR0JBTGNHRGZzcVBObzNKcFpIMjVMcnd4bDNGeWZt
VExKUGdtRUh5KzcvcUJ0eVlBTEp1cC9McGRxcQpRcjkraTBpcFdLcWs3cG5TUi9w
aFo4S3pnR1lnVGJWUDZyV2NGQXZvWEhQWXVmc1d6OVp2SGY3N0drYVZZSTJSCkVq
TEtaL1FMRG9rYVFKOFpHeWNpUnJ3ZHlRdHMyTUxZc00rRUQ3bmhHZzdtR2N2eWZC
SWZBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVj
dGlvbi1wb2ludCB5bjN4NG9scTdsYm1ic3ptanlsZ29ybmhvemliZ2V5ZQppcC1h
ZGRyZXNzIDk0LjIzLjE1MC44MQpvbmlvbi1wb3J0IDQ0Mwpvbmlvbi1rZXkKLS0t
LS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU94ajNzT2syb3g3
dzU5aXdhejl6WHc2UktvdjJXYUh6TWVvbjBiWlVVQXVHcWlKT01ONEt3RkQKMlNS
LzBrSUY1UjIyV3I4a2x0cXQxbWlTY0tvWk9KU2MrYXVVVjR6TXl2NmE5bnl2cXJt
amhDYWJqSlFoQ0M4VQpoT3ZrL2N3K1MvZHZnQXFGTkdnTzNHV0RrSnI3bC9BTXh5
alhVa1FKYnVjb1JiWGkwbU56QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBL
RVktLS0tLQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0t
LS0KTUlHSkFvR0JBTVJDYWJHdWI3Mk1xSndqMHJXRnArZW5xSzRzMVBEeGZUVDUx
Zmcwdkd0bStxM1E0azFtUm1tVApiNkc3OTNNOVV6WnN4dVNKbDRSOVJyZEJaM1pt
OGRmMDU2cEUvSmJ0Q2NWVnlPb0daZlVsWHhXaDM0c2RZdU4xCkZGb1Iva0JlLzBF
aWtBSWI5eGsyS001SjlKMGEyc1A0UTNhL2NGOWJkNjhpMWlaSmIySWhBZ01CQUFF
PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCmludHJvZHVjdGlvbi1wb2lu
dCBoemo1aGY0NXdiN3AyNDNnbWhldGppbzYyZmFzcG51ZQppcC1hZGRyZXNzIDIx
Ny43OS4xNzkuMTc3Cm9uaW9uLXBvcnQgOTAwMQpvbmlvbi1rZXkKLS0tLS1CRUdJ
TiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQU5xY2R0YTQvOUFFYzkyMjJx
YUVnVTNSQ1E0ZEVGTnlDSDNDbTVTNGFDa2dxbHp0VmJPSlBlVmQKVjJaTjk4dW8x
OGlXa3JySENiZUdTWTVqdkkvdTFlUzFydTNNTkM1NTBhNDE3RHdFUGlaUWJxMitO
N1dGYisxbwpOa2x2TkllZTZGMDllb2FYMExuVGJjR1RheGJLaHF0cWh4cGJvYTVJ
RUV0L05CajRmNE05QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0t
LQpzZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlH
SkFvR0JBTzZzbjNzekJXVGxjQVAvV1lIQ2ZzVmVnSDBPNmNlcHlWRVllOW82YzQ4
cGh6VDBoZzFnWmJMdApOS3lqM2xWR1RaYVFxY3Jvak16bzhlbkEwR2VyeGsrWVpF
THV3eDRCYmIraUk5d1gvbmJib3ptejhLZjhNdnVGCmNkakFDalEwV3liVXBtcWdk
TXBpVHc4SFNSbWh0SWlsQXE1L1VnYzNTaVRQbHlqWVYxN1BBZ01CQUFFPQotLS0t
LUVORCBSU0EgUFVCTElDIEtFWS0tLS0tCgo=
-----END MESSAGE-----
signature
-----BEGIN SIGNATURE-----
XkVVwRd1reFUb0KqdtYUWcLUCQduq7GnGJ8IpNYbsI4x8LadiRi9gxABv8E4OjYQ
5CiP6qso+SMieOP7PEQK67+VMnrUaPUsldDjYdSkWCTNSPgbaXOasSFxJ0pZeQXx
NwjHDSI4mD57pkSzvPgd+t/hrA3AFAWZu49eUw4BYwc=
-----END SIGNATURE-----
"""


hs_example2 = """HTTP/1.0 200 OK
Date: Wed, 20 Mar 2019 21:17:16 GMT
Content-Type: text/plain
X-Your-Address-Is: 104.192.88.97
Content-Encoding: identity
Content-Length: 3253
Pragma: no-cache

rendezvous-service-descriptor expocwozpjpjce7kfcdyu3et25aswqdf
version 2
permanent-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALdj5MFZtlrjI54ousrBzA3fSyfn0NC32OBhl61BLgO67vPBiIiFFzo9
YIqa4h3jZQrxdI3MeK4xTLQ6HhnQXvcM+ZR57o5zTR7fpqra89i75rwUjW5wqc9O
3roxzt1UWbJBtbzOT9FYxGSIczsYdG6MQRg9BK/2v391Oz9NbDb1AgMBAAE=
-----END RSA PUBLIC KEY-----
secret-id-part 2o5f46v3wjaoysjde3z2tjkax5unwp4z
publication-time 2019-03-20 21:00:00
protocol-versions 2,3
introduction-points
-----BEGIN MESSAGE-----
aW50cm9kdWN0aW9uLXBvaW50IHlzbmJvNWlxemt0Zmh3dGhlNjdxNGI3M3A1bGti
NGU1CmlwLWFkZHJlc3MgMTM2LjI0My43MC4xOTgKb25pb24tcG9ydCA5MDAxCm9u
aW9uLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JB
T01uajFoQUR4dDcrT0xqVnJxRnFWdGFaQ1kranNqdlk1OTNDMktYdnVJT3dTcXVB
SUZHamVLQgpnM2dEVjZRckZyN0ZKSGZjOTZiTkVRa2I2RmhUQkFydVB2OTJYQ3Aw
TVdsTzBhS2ZWNTZLckgrZXg0ZWRRUmxXClUzY2l3c3IrMStVclcwOS9ob0twb29K
WGhaSUZJRjg3d1RvYlFxbVM4LzFnMzBQR2tHWGhBZ01CQUFFPQotLS0tLUVORCBS
U0EgUFVCTElDIEtFWS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBV
QkxJQyBLRVktLS0tLQpNSUdKQW9HQkFOUERQZkFSTS9BbXRQYUJCZDMyY3FvWVZN
Vit4WkY5djI0aVY0cTZxODRTaEM0Z3YzMFI4cjZHCldJbjErZUJSYWUyZXkzVlVn
S21BYmU2TzJ0SUNmN3Q2QzY0REFBZFVVcVljc1Vka2pmQy8yQ1IwaXpjaExuK1gK
NWdHSU0rbmpseGppRVFEZHZWaDljWjlzV0RtUzdhYmkvbXNkMmRjZFhXV3QwSkRy
WlJ4dEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9k
dWN0aW9uLXBvaW50IGZrNjR5d3JnazNnNmR4M2FjY2psempxbW9yZTdwd2t3Cmlw
LWFkZHJlc3MgNzguMTI5LjIwOC4xODQKb25pb24tcG9ydCA0NDMKb25pb24ta2V5
Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFKZCtyeVFu
RHl3eGRUeTZKNXlQbGJmVmFFWWxNenF0WEZhZTVtSkJGdDdCRHhXQjRDZ1lFOG9I
Ckd4ZTg4UXpjTFUvd0FEZmVSaDVMaVpweWdhY0J6M1VRY04yYklGWm9Bc3hmMU5W
R3NLR2xrV3RSTWl0ZmMyWjkKcW8yMVpHdUNMUTZDb3RTeG5sUXVJNWxaR1ZkQ3kx
WGt0d2lzK2VGL2RiRWNra3dwS3FoRkFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJM
SUMgS0VZLS0tLS0Kc2
"""


def test_hs_parser(hs_example):
    res = HSDescriptorParser.parse(hs_example)
    print(res)


@pytest.fixture
def ip_example():
    return """introduction-point ysnbo5iqzktfhwthe67q4b73p5lkb4e5
ip-address 136.243.70.198
onion-port 9001
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOMnj1hADxt7+OLjVrqFqVtaZCY+jsjvY593C2KXvuIOwSquAIFGjeKB
g3gDV6QrFr7FJHfc96bNEQkb6FhTBAruPv92XCp0MWlO0aKfV56KrH+ex4edQRlW
U3ciwsr+1+UrW09/hoKpooJXhZIFIF87wTobQqmS8/1g30PGkGXhAgMBAAE=
-----END RSA PUBLIC KEY-----
service-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANPDPfARM/AmtPaBBd32cqoYVMV+xZF9v24iV4q6q84ShC4gv30R8r6G
WIn1+eBRae2ey3VUgKmAbe6O2tICf7t6C64DAAdUUqYcsUdkjfC/2CR0izchLn+X
5gGIM+njlxjiEQDdvVh9cZ9sWDmS7abi/msd2dcdXWWt0JDrZRxtAgMBAAE=
-----END RSA PUBLIC KEY-----
introduction-point fk64ywrgk3g6dx3accjlzjqmore7pwkw
ip-address 78.129.208.184
onion-port 443
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJd+ryQnDywxdTy6J5yPlbfVaEYlMzqtXFae5mJBFt7BDxWB4CgYE8oH
Gxe88QzcLU/wADfeRh5LiZpygacBz3UQcN2bIFZoAsxf1NVGsKGlkWtRMitfc2Z9
qo21ZGuCLQ6CotSxnlQuI5lZGVdCy1Xktwis+eF/dbEckkwpKqhFAgMBAAE=
-----END RSA PUBLIC KEY-----
service-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANw4LrTMxv1lXQp2XgKXUklE/KgdHB3bSQ+f8FzIIEat+ndVvTuq4ILp
PngUxqTS8ulc0ZMJ+kLezLBzYupVZy+c4Lhc9SCROTtz93yoO45NPtcszKaNO1+K
kf95gp5BHvuC51OD4UGJOgaQzusRjrbfDc2KB2D5g+scok86qgShAgMBAAE=
-----END RSA PUBLIC KEY-----
introduction-point 3ugi53c4uqbkt6sepdyqymneid3r62ef
ip-address 195.201.9.37
onion-port 143
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJwz6KYUdMpK4/g5LurMLE53kWNU5oUzdXZTHc7/zNcdYKejAYwADVqM
d+jJjlNfi5XEUAZmTVFP2VwAGBza86hlfApg01kvLA9ptDOsgtrGhc8kYT6nQYX+
gVvSRyXDMNOMlZRA9ALA8wmhmFM/3T5BvjpsV90xum56qnWp0lvnAgMBAAE=
-----END RSA PUBLIC KEY-----
service-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAN44XsgtoiYfSGUSmiudOPJQo96Mhd/dcuzQbYzhK1X6F7FvmMcJWhLK
LO/0dedGvqikKwEuNjhkGawwqYudL3sZ6AUyxY9wgfzznfWYbLFMx9KpZzh76n6c
sObvfg6Gt0HmZIh+nJdhF1n8u/xYZZ4TyL8jGg+eyG/aJ1jIfnoPAgMBAAE=
-----END RSA PUBLIC KEY-----
"""


def test_ip_parser(ip_example):
    res = IntroPointParser.parse(ip_example)
    print(res)


@pytest.fixture
def rd_example():
    return """router Nyx 51.15.252.1 9001 0 9030
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABph4ATKUIStvlLeIF/2rGBv6k+/8sK05mjCtRjeXH5lJBfECAQAgBACuN8aH
zaPSQqkRZi9nU79oNKT/e1pSsBw8u0YeHF6SfVUDl/yIU9i53fU9eF5bKB41b7Pn
r7xCUwOJnEXwQLoZ5wr5oFQKMNzsgEzUwj20K0NGQ3djZCEtt8vjiqflTQw=
-----END ED25519 CERT-----
master-key-ed25519 rjfGh82j0kKpEWYvZ1O/aDSk/3taUrAcPLtGHhxekn0
platform Tor 0.3.5.8 on Linux
proto Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-4 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2
published 2019-03-31 11:43:32
fingerprint 8532 DE42 43E4 949E 4EA8 6E88 CDCA 6821 582F 1A13
uptime 2840486
bandwidth 1073741824 1073741824 24702282
extra-info-digest FFDAB70266F42AE8938EC1C0E6DC1A275DD903FE bCEVMfYHbSxL6Th0iJj0Wo8HZrzLnyqDvlheyO1JzNE
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALlYKkE6C0RMPe6YbUtlP5Ucu90Kj8GnsYD0Hwbh7tqL/QkXFSPRnoA8
8fGdp/jlNhQt/Asfbsqq9H+7FLQ6r8rZG1/ndMO8g+khobBvddFxr0JBn5BvZO8h
MJAbg8K/DVSnfxIaJrhxN/VWUjEmH9vwpmyuNYIXZKRHfqszn1G1AgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMRcnxPGmSTWelnSD6FVET7L88E2xf3vd17cB2JDTWdw0gIGM7aL4WVL
P8xuVqshwmlqXGiExtruqZUVWD8M1pAQwNoILCpqJJ5U1LZyqmRoNlkRjcCKuaJw
RiSsmJCvkCZzcJ3PBiJbhMxqKyweGWSqsB2bRNpSb8aZLIIOZnzXAgMBAAE=
-----END RSA PUBLIC KEY-----
onion-key-crosscert
-----BEGIN CROSSCERT-----
HiWs9Bo11xyyJs+i/8AdpNDoQkdNVoTuvMFNnDamYceEUTWaoxDazk3OIFkiIHqe
wPI0AKF5+vTUWHfRBB4AuBYgoLMxAAPNtbSgKnI9c+5pKwsWeHJs89F0jTIulNYs
Es1T9HQq+HGWRH8M0Dbv6o/W5MKLppvqRIhbXXRrR+I=
-----END CROSSCERT-----
ntor-onion-key-crosscert 1
-----BEGIN ED25519 CERT-----
AQoABpjcAa43xofNo9JCqRFmL2dTv2g0pP97WlKwHDy7Rh4cXpJ9APezxMtt8tMB
tpDMZnC+Hq9pK62Yu6Na3H+T0+fdme8CmhXa9pQ8NgCpeW7Es9oNXaCev8BcMol/
6AFJ3vFidAI=
-----END ED25519 CERT-----
family $13E8EB1D9FD7470AA87A47DC93538E88340A0903 $157106182B9F33663CAEDCD883D302316331DE5E $2C5FDD910AE3E21C0B6F9DD4BF397F570C8358FA $3844DFD3446832A3C8A137EEA616D4EEB370C788 $42E0FB190D20522C6C8C71E42B71DA33AC7A780E $4DDBC57BA2A63F0439FD41D92BFF8E141CC61213 $54FA84FF74B0C2BAC45CEADB4BF9C9CAEF72020F $67469C0671BF8D4BECB11F006AD541E9BC54EBCB $69D22FAEE5D4E18A098D5DEF68EAEE8D24F53CCA $70A81E423F94A9BF58D2FF432BBF59FA73426DB6 $8154154C636EC317C7165FD839F34F79963376C1 $88C3708A9D71ECEC1910B63C3FAA5BF60CD7E199 $8C34A154997812D1396BC462A42DA0A59B55952D $AEA760EE120B630262C70C1C11D4158BBF12C602 $B5EDD091D81655C2EBADB38065A868AA20259AC3 $B756D7123D759EAB62CB6A09148AD65AC216F3E3 $C79517FFC1327B0D4E86218A34C8E2570F338CF9 $C8850DE0EBC07481808F32F2BAA76CA65CB659FB $CE946DFEC40A1BFC3665A4727F54354F57297497
hidden-service-dir
contact abuse [AT] torworld.org - BTC 34yFiqwbcUA5MYSvUcpjqARvhoTwMFjmPs
ntor-onion-key owtGGV469gdDNIWfnIlIHgR7CvM0Ak5VwLiZCtBgtzc=
reject 0.0.0.0/8:*
reject 169.254.0.0/16:*
reject 127.0.0.0/8:*
reject 192.168.0.0/16:*
reject 10.0.0.0/8:*
reject 172.16.0.0/12:*
reject 51.15.252.1:*
reject 5.157.0.0/18:*
reject 5.188.216.0/24:*
reject 31.11.43.0/24:*
reject 37.139.49.0/24:*
reject 37.9.42.0/24:*
reject 37.9.53.0/24:*
reject 46.148.112.0/24:*
reject 46.148.120.0/24:*
reject 46.148.127.0/24:*
reject 46.161.56.0/24:*
reject 46.161.57.0/24:*
reject 46.161.58.0/24:*
reject 46.161.59.0/24:*
reject 46.161.60.0/24:*
reject 46.161.61.0/24:*
reject 46.161.62.0/24:*
reject 46.161.63.0/24:*
reject 46.243.140.0/24:*
reject 46.243.142.0/24:*
reject 46.243.173.0/24:*
reject 46.29.248.0/21:*
reject 46.8.255.0/24:*
reject 47.104.0.0/13:*
reject 49.12.0.0/16:*
reject 49.13.0.0/16:*
reject 79.110.22.0/24:*
reject 79.133.107.0/24:*
reject 81.94.43.0/24:*
reject 83.217.11.0/24:*
reject 84.19.170.240/28:*
reject 85.121.39.0/24:*
reject 85.93.5.0/24:*
reject 91.200.12.0/22:*
reject 91.200.164.0/24:*
reject 91.200.81.0/24:*
reject 91.200.82.0/24:*
reject 91.200.83.0/24:*
reject 91.207.4.0/22:*
reject 91.209.12.0/24:*
reject 91.212.124.0/24:*
reject 91.213.126.0/24:*
reject 91.216.3.0/24:*
reject 91.217.10.0/23:*
reject 91.220.101.0/24:*
reject 91.220.163.0/24:*
reject 91.220.62.0/24:*
reject 91.224.160.0/23:*
reject 91.225.216.0/22:*
reject 91.226.92.0/22:*
reject 91.230.252.0/23:*
reject 91.235.2.0/24:*
reject 91.236.74.0/23:*
reject 91.238.82.0/24:*
reject 91.243.90.0/24:*
reject 91.243.91.0/24:*
reject 91.243.93.0/24:*
reject 93.179.88.0/24:*
reject 95.181.176.0/24:*
reject 95.181.177.0/24:*
reject 95.181.182.0/24:*
reject 95.181.183.0/24:*
reject 95.181.216.0/24:*
reject 95.181.217.0/24:*
reject 95.181.219.0/24:*
reject 95.182.79.0/24:*
reject 95.85.80.0/24:*
reject 95.85.81.0/24:*
reject 103.215.80.0/22:*
reject 103.63.0.0/22:*
reject 113.212.64.0/19:*
reject 141.101.132.0/24:*
reject 141.101.201.0/24:*
reject 141.136.27.0/24:*
reject 146.185.200.0/24:*
reject 146.185.201.0/24:*
reject 146.185.202.0/24:*
reject 146.185.203.0/24:*
reject 146.185.204.0/24:*
reject 146.185.205.0/24:*
reject 146.185.206.0/24:*
reject 150.129.40.0/22:*
reject 151.237.176.0/20:*
reject 159.174.0.0/16:*
reject 172.80.0.0/17:*
reject 176.53.112.0/20:*
reject 176.97.116.0/22:*
reject 178.159.97.0/24:*
reject 178.16.80.0/20:*
reject 178.57.65.0/24:*
reject 178.57.66.0/24:*
reject 178.57.67.0/24:*
reject 178.57.68.0/24:*
reject 179.61.200.0/23:*
reject 181.214.37.0/24:*
reject 181.215.39.0/24:*
reject 185.101.68.0/24:*
reject 185.101.71.0/24:*
reject 185.103.252.0/23:*
reject 185.106.104.0/23:*
reject 185.106.92.0/24:*
reject 185.106.94.0/24:*
reject 185.112.102.0/24:*
reject 185.115.140.0/24:*
reject 185.127.24.0/22:*
reject 185.129.148.0/23:*
reject 185.137.219.0/24:*
reject 185.14.192.0/24:*
reject 185.14.193.0/24:*
reject 185.14.195.0/24:*
reject 185.146.168.0/22:*
reject 185.154.20.0/22:*
reject 185.159.36.0/22:*
reject 185.169.228.0/22:*
reject 185.2.32.0/24:*
reject 185.71.0.0/22:*
reject 188.247.135.0/24:*
reject 188.247.230.0/24:*
reject 188.247.232.0/24:*
reject 188.68.0.0/24:*
reject 188.68.1.0/24:*
reject 188.68.3.0/24:*
reject 188.72.126.0/24:*
reject 188.72.127.0/24:*
reject 188.72.96.0/24:*
reject 191.101.24.0/24:*
reject 191.101.54.0/23:*
reject 191.96.170.0/24:*
reject 191.96.174.0/24:*
reject 193.105.171.0/24:*
reject 193.138.244.0/22:*
reject 193.93.192.0/24:*
reject 193.93.195.0/24:*
reject 194.29.185.0/24:*
reject 195.182.57.0/24:*
reject 195.190.13.0/24:*
reject 195.191.56.0/23:*
reject 195.225.176.0/22:*
reject 204.225.16.0/20:*
reject 212.92.127.0/24:*
reject 46.8.44.0/23:*
reject 46.98.64.0/18:*
reject 68.119.232.0/21:*
reject 68.215.0.0/16:*
reject 69.244.0.0/14:*
reject 70.111.0.0/16:*
reject 70.126.0.0/15:*
reject 112.78.2.0/24:*
reject 193.9.28.0/24:*
reject 195.20.40.0/21:*
reject 5.8.37.0/24:*
reject 5.101.218.0/24:*
reject 5.101.221.0/24:*
reject 79.110.17.0/24:*
reject 79.110.18.0/24:*
reject 79.110.19.0/24:*
reject 79.110.25.0/24:*
reject 93.179.89.0/24:*
reject 93.179.90.0/24:*
reject 93.179.91.0/24:*
reject 185.46.84.0/22:*
reject 185.50.250.0/24:*
reject 185.50.251.0/24:*
reject 193.9.158.0/24:*
reject 5.196.26.96:*
reject 23.235.209.11:*
reject 23.92.87.202:*
reject 27.254.151.81:*
reject 27.254.152.29:*
reject 27.254.40.113:*
reject 27.254.41.206:*
reject 27.254.44.105:*
reject 27.254.61.110:*
reject 27.254.85.27:*
reject 27.254.85.49:*
reject 36.39.155.98:*
reject 36.66.209.21:*
reject 36.72.228.22:*
reject 36.76.176.64:*
reject 37.203.213.110:*
reject 46.26.129.203:*
reject 46.34.160.34:*
reject 50.118.100.49:*
reject 54.37.96.109:*
reject 58.195.1.4:*
reject 59.157.4.2:*
reject 60.13.186.5:*
reject 60.241.184.209:*
reject 62.75.132.67:*
reject 63.249.152.74:*
reject 64.127.71.73:*
reject 64.182.6.61:*
reject 64.85.233.8:*
reject 66.117.5.245:*
reject 66.70.134.137:*
reject 66.70.190.236:*
reject 68.65.122.86:*
reject 74.124.194.43:*
reject 77.104.143.180:*
reject 77.227.184.45:*
reject 77.228.191.183:*
reject 78.108.82.18:*
reject 78.108.83.153:*
reject 78.108.87.155:*
reject 78.108.89.85:*
reject 78.108.93.91:*
reject 78.108.95.116:*
reject 78.108.95.207:*
reject 78.138.104.167:*
reject 78.138.88.232:*
reject 79.170.44.115:*
reject 79.187.34.150:*
reject 79.188.45.226:*
reject 80.48.160.146:*
reject 80.52.222.10:*
reject 80.65.93.241:*
reject 83.0.245.234:*
reject 83.1.195.232:*
reject 83.17.220.66:*
reject 83.212.110.172:*
reject 83.212.112.80:*
reject 83.212.117.233:*
reject 83.212.120.81:*
reject 83.220.128.111:*
reject 83.220.144.107:*
reject 83.220.144.30:*
reject 84.19.190.8:*
reject 84.19.191.164:*
reject 85.117.35.21:*
reject 85.25.185.254:*
reject 86.104.134.144:*
reject 87.118.102.19:*
reject 87.118.90.136:*
reject 87.119.194.135:*
reject 87.236.210.110:*
reject 87.236.210.124:*
reject 87.237.198.245:*
reject 87.246.143.242:*
reject 87.254.167.37:*
reject 89.232.63.147:*
reject 91.108.176.118:*
reject 91.121.78.51:*
reject 91.201.202.12:*
reject 91.208.144.164:*
reject 92.36.213.75:*
reject 93.153.195.181:*
reject 93.170.128.136:*
reject 93.170.130.147:*
reject 93.170.131.108:*
reject 93.171.202.191:*
reject 93.65.43.220:*
reject 94.103.36.55:*
reject 95.169.184.25:*
reject 95.169.184.7:*
reject 95.169.190.104:*
reject 95.62.197.90:*
reject 96.31.35.51:*
reject 103.19.89.118:*
reject 103.230.84.239:*
reject 103.26.41.71:*
reject 103.4.52.150:*
reject 103.53.172.20:*
reject 103.53.172.96:*
reject 103.59.164.125:*
reject 103.7.56.119:*
reject 103.7.59.135:*
reject 103.221.222.65:*
reject 104.244.120.12:*
reject 104.247.76.199:*
reject 109.127.8.242:*
reject 109.127.8.246:*
reject 109.199.98.63:*
reject 109.229.210.250:*
reject 109.229.36.65:*
reject 109.237.111.168:*
reject 109.248.200.23:*
reject 110.138.108.142:*
reject 110.164.126.64:*
reject 110.164.205.225:*
reject 111.67.15.173:*
reject 111.67.16.254:*
reject 113.29.230.24:*
reject 115.146.59.207:*
reject 120.63.157.195:*
reject 120.63.175.225:*
reject 124.110.195.160:*
reject 128.210.157.251:*
reject 130.206.78.158:*
reject 137.74.6.95:*
reject 138.100.137.61:*
reject 143.225.116.108:*
reject 147.156.165.26:*
reject 148.163.100.151:*
reject 150.244.121.149:*
reject 151.97.190.239:*
reject 151.97.80.16:*
reject 154.66.197.59:*
reject 158.110.80.108:*
reject 158.69.255.67:*
reject 161.67.132.25:*
reject 162.223.94.56:*
reject 162.255.119.249:*
reject 172.81.119.140:*
reject 177.4.23.159:*
reject 177.70.107.137:*
reject 177.70.122.13:*
reject 177.70.122.193:*
reject 177.70.123.117:*
reject 177.70.123.128:*
reject 177.70.123.8:*
reject 177.70.123.90:*
reject 177.70.98.122:*
reject 177.70.98.242:*
reject 178.210.173.46:*
reject 178.250.241.22:*
reject 178.250.243.146:*
reject 178.250.245.138:*
reject 178.250.246.89:*
reject 178.32.255.132:*
reject 178.32.52.15:*
reject 180.182.234.200:*
reject 180.241.47.130:*
reject 180.250.210.23:*
reject 180.250.28.38:*
reject 181.136.26.124:*
reject 185.15.185.201:*
reject 185.15.185.209:*
reject 185.19.92.70:*
reject 185.59.28.14:*
reject 185.61.152.30:*
reject 185.242.179.15:*
reject 185.242.179.16:*
reject 186.202.153.34:*
reject 186.64.122.105:*
reject 187.141.112.98:*
reject 187.141.12.161:*
reject 187.174.252.247:*
reject 188.218.158.126:*
reject 188.219.154.228:*
reject 188.240.2.93:*
reject 188.241.140.212:*
reject 188.241.140.222:*
reject 188.241.140.224:*
reject 188.84.140.44:*
reject 188.85.248.131:*
reject 190.128.122.234:*
reject 190.128.29.1:*
reject 190.15.192.25:*
reject 190.183.59.133:*
reject 190.7.28.147:*
reject 191.252.104.136:*
reject 191.252.128.181:*
reject 191.252.130.32:*
reject 191.252.132.201:*
reject 191.252.134.38:*
reject 191.252.135.80:*
reject 191.252.136.74:*
reject 191.252.140.148:*
reject 191.252.140.199:*
reject 191.252.140.212:*
reject 191.252.141.145:*
reject 191.252.142.98:*
reject 191.252.143.96:*
reject 191.252.2.161:*
reject 192.100.170.12:*
reject 192.64.11.244:*
reject 192.64.9.116:*
reject 192.99.37.46:*
reject 193.146.210.69:*
reject 193.218.145.184:*
reject 193.218.145.32:*
reject 193.218.145.50:*
reject 194.144.188.70:*
reject 195.117.119.187:*
reject 195.205.24.101:*
reject 198.50.173.86:*
reject 198.54.126.39:*
reject 199.187.129.193:*
reject 199.201.121.169:*
reject 199.201.121.185:*
reject 199.246.2.104:*
reject 199.7.234.100:*
reject 200.0.24.42:*
reject 200.116.206.58:*
reject 201.149.83.183:*
reject 201.232.32.124:*
reject 202.115.63.125:*
reject 202.144.144.195:*
reject 202.150.213.85:*
reject 202.150.213.93:*
reject 202.28.32.110:*
reject 202.28.32.20:*
reject 202.29.22.38:*
reject 202.29.230.198:*
reject 202.67.13.107:*
reject 203.170.192.150:*
reject 203.170.192.240:*
reject 203.170.193.23:*
reject 203.24.188.166:*
reject 208.83.210.109:*
reject 208.93.233.58:*
reject 209.99.40.225:*
reject 209.164.84.70:*
reject 209.182.193.155:*
reject 209.182.199.168:*
reject 209.182.208.165:*
reject 209.182.213.90:*
reject 209.191.185.67:*
reject 210.37.11.238:*
reject 210.4.76.221:*
reject 210.46.85.150:*
reject 210.83.80.26:*
reject 212.252.45.46:*
reject 212.44.64.202:*
reject 212.72.132.138:*
reject 213.147.67.20:*
reject 213.185.88.41:*
reject 213.185.88.60:*
reject 213.205.38.29:*
reject 213.25.134.75:*
reject 216.176.100.240:*
reject 216.215.112.149:*
reject 216.59.16.171:*
reject 222.124.202.178:*
reject 222.124.206.41:*
reject 222.29.197.232:*
reject 46.173.218.123:*
reject 91.219.29.41:*
reject 195.208.1.101:*
reject 5.79.71.205:*
reject 5.79.71.225:*
reject 46.244.21.4:*
reject 50.21.181.152:*
reject 50.63.202.35:*
reject 52.5.245.208:*
reject 64.71.166.50:*
reject 67.215.255.139:*
reject 74.200.48.169:*
reject 74.208.153.9:*
reject 74.208.164.166:*
reject 74.208.64.191:*
reject 85.17.31.122:*
reject 85.17.31.82:*
reject 87.106.149.145:*
reject 87.106.149.153:*
reject 87.106.18.112:*
reject 87.106.18.141:*
reject 87.106.190.153:*
reject 87.106.20.192:*
reject 87.106.24.200:*
reject 87.106.253.18:*
reject 87.106.26.9:*
reject 95.211.230.75:*
reject 104.244.14.252:*
reject 109.70.26.37:*
reject 144.217.74.156:*
reject 146.148.124.166:*
reject 148.81.111.111:*
reject 151.80.148.103:*
reject 176.58.104.168:*
reject 178.162.203.202:*
reject 178.162.203.211:*
reject 178.162.203.226:*
reject 178.162.217.107:*
reject 184.105.192.2:*
reject 192.0.72.20:*
reject 192.0.72.21:*
reject 192.169.69.25:*
reject 192.42.116.41:*
reject 192.42.119.41:*
reject 193.166.255.170:*
reject 193.166.255.171:*
reject 204.11.56.48:*
reject 208.91.197.46:*
reject 212.227.20.93:*
reject 213.165.83.176:*
reject 216.218.135.114:*
reject 216.218.185.162:*
reject 216.218.208.114:*
reject 216.66.15.109:*
reject 72.55.186.0/24:*
reject 174.142.230.0/24:*
reject 184.107.100.0/24:*
reject 184.107.101.0/24:*
reject 184.107.116.0/24:*
reject 108.163.147.0/24:*
reject 198.72.104.0/24:*
reject 67.205.125.0/24:*
reject 67.205.105.0/24:*
reject 184.107.95.0/24:*
reject 5.145.168.0/21:*
reject 37.235.53.0/24:*
reject 37.252.96.0/24:*
reject 77.81.112.0/22:*
reject 77.81.116.0/22:*
reject 91.192.108.0/22:*
reject 93.93.64.0/21:*
reject 151.236.23.0/24:*
reject 158.255.238.0/24:*
reject 185.49.192.0/22:*
reject 185.50.196.0/22:*
reject 185.66.175.0/24:*
reject 185.76.77.0/24:*
reject 185.86.210.0/24:*
reject 185.104.152.0/24:*
reject 185.129.249.0/24:*
reject 192.71.213.0/24:*
reject 195.78.228.0/22:*
reject 23.217.172.41:*
reject 23.217.173.70:*
reject 23.217.161.62:*
reject 23.217.161.153:*
reject 23.235.33.144:*
accept *:20-21
accept *:43
accept *:53
accept *:80
accept *:110
accept *:143
accept *:220
accept *:443
accept *:873
accept *:989-990
accept *:991
accept *:992
accept *:993
accept *:995
accept *:1194
accept *:1293
accept *:3690
accept *:4321
accept *:5222-5223
accept *:5228
accept *:9418
accept *:11371
accept *:64738
reject *:*
tunnelled-dir-server
router-sig-ed25519 JWCYm75YxNMFHgUUI4cJyRgDGwcIedVSYIQERCdJFlRMjxPS9LOvcUzuv4rBZQLC3RAA80j7D5udcfeW0R0SDw
router-signature
-----BEGIN SIGNATURE-----
SLhtm94eITNNjle4PRclrt7uW/PswS5ByuQfQJ50m5tD+ENoZQx02HNWhD2Ovw8D
LEAPxV9sbjt8fzJ/EIzdl8vh+Nz2SIPJFBU1dkRkWSVE+Is0JPRqNKlzpVpWfW8h
zKOoQK1MV0YfYNhvLoSV9li7ed1GJrw9kmWOUgoRV3s=
-----END SIGNATURE-----
"""


def test_rd_parser(rd_example):
    res = RouterDescriptorParser.parse(rd_example)
    print(res)


@pytest.fixture
def rd_example2():
    return """router FalkensteinTor02 5.9.43.211 9001 0 0
identity-ed25519
-----BEGIN ED25519 CERT-----
AQQABsdtAbJp6YkI/WzQR8BP/30zhjSwogIlmyv6R/H5ru6ZgRhmAQAgBAATlA+2
LrLjDwoljVbbgDmbudSPI8ZcxiLR0qDaIBslLAjhjMMY5E+Joq39z+uytdAxKLSl
LtjMg4X3WRb3jGy+8gVbiYgpbCjvSnfQbEHmm8C6VxHWoMQShsT4LwPJiQs=
-----END ED25519 CERT-----
master-key-ed25519 E5QPti6y4w8KJY1W24A5m7nUjyPGXMYi0dKg2iAbJSw
or-address [2a01:4f8:161:32c7::2]:9001
platform Tor 0.4.5.0-alpha-dev on Linux
proto Cons=1-2 Desc=1-2 DirCache=1-2 FlowCtrl=1 HSDir=1-2 HSIntro=3-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-3
published 2020-08-20 09:56:35
fingerprint 0512 FE6B E9CC A0ED 1331 52E6 4010 B2FB A141 EB10
uptime 64805
bandwidth 31457280 73400320 33471488
extra-info-digest F631D985A46F850C46FE2355947D36CA45DBE335 M/2vGW74uurcpt0e+7/EJqOV4LpoJRYAZ+G7I9f58L4
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMC8N8BeGYY6vt/QO1QFd0puJpEZq83iISrgGL1KAKleTGbqLpv7WBH0
SKIDFpleHiElq74yC6yXZf9cDCfXzctpVWa1zPI/ISCJaxFEbDLMLTgaRy7PGA9d
Sxze6wrlo+eXmLc9qSrJLyNScMpVRjL748YXxypbL+2RbHCfB7o1AgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAL+bi9Kfe8dhwaaq8c5kcAXbCHUyvfx9gVBCuDj7jAOQKy16zBfuUh7q
614bwRiD4sFC4QFq+j43EjJgXeReAH9sDeWJxP3Q9muEuCcqfmf+OAlYjruXEYrT
LEO6q2Hd22nJ9WaxEHgvSCvECTNmODUdgP0DJpkKcwks3VM4wamZAgMBAAE=
-----END RSA PUBLIC KEY-----
onion-key-crosscert
-----BEGIN CROSSCERT-----
Jq35dkFnNz2asXwJfQR57FRySoaluo1FEhFe5l349iLKy1Nd9U2YAYErg9845GRp
BD1OYpqMYvtgxOvNz6ltsbfz6eHaOxJhnXumLyv59cDtLAQ+Piicar9EbPmBCQsp
c0K9YfijqJ8y4EbEGpCW01nTglqKr+527wD+Hbb346g=
-----END CROSSCERT-----
ntor-onion-key-crosscert 1
-----BEGIN ED25519 CERT-----
AQoABsh6AROUD7YusuMPCiWNVtuAOZu51I8jxlzGItHSoNogGyUsAI8evueV8KZm
nXoT6qtg208Dbmh19z0jPm745LXgElQ8U/CTLOSVGW1fMkVs0zPjyvpSVrTjH5fz
LRcQgJ/X6gM=
-----END ED25519 CERT-----
family $0512FE6BE9CCA0ED133152E64010B2FBA141EB10 $08F06A0DDAFABF9A26FCB2E392A1435F9E048216 $0A7208B8903DD3FF5CDFA218A3823AF498CE69CE $128FC6D8FBF753121C5662FEE309CCD47B64BA6B $599A708756048993A1029B2775EEF8C9E40BB640 $695D811B130673C2DE8DCFC5A9E742790BD25066 $7185B69E3267E71D0E4CBE30209677205DEA5E67 $8E5F4EE45E0631A60E59CAA42E1464FD7120459D $B70BD334FFEE23E653B75219AE12CF0236BCFCBB $B76A047C20D3E4F9B5A64428298DA55A90D62472 $D7230F4F13324A28C308AF94E2385D0A7F1B05F9 $DEF8C760A79FEF2358E03AE5A1950086ABEB953E $F0F13714732C347312426EC2B8D5C4940EAA45BA $F5C3DA7642BB037E0D279359AE88CD7FC03A98A0
hidden-service-dir
contact <tor AT afo MINUS tm DOT org>
ntor-onion-key xbqQBTwgBWJxkxBrHuHsKp5WyZ4yof09zsnGZMXB+Rk
reject *:*
tunnelled-dir-server
router-sig-ed25519 Hk2KgDHyw7OAo8g79eo7mEHK/k3UszFAH1Fkole70BIdUDOvA/8oHwSA2aO+Rp1i6v0I/LlKr0u8/pqDzGd7Bg
router-signature
-----BEGIN SIGNATURE-----
UmJeAncV38dJBgsKSVxw14cRdo/YTu3owAa+YJOWkWsNl03UATGeNAWQGc2ZwhI3
nk4ha7uQ254z5uDyWT5vD7QbPREcFbWvif7EWRqqBi0kdwSClYzMI/+4dFh+dz3v
jvfDaEld8KBz3UxumcxRnswmDzC9zsS3Bq/LxQ7LrR4=
-----END SIGNATURE-----
"""


def test_rd_parser2(rd_example2):
    res = RouterDescriptorParser.parse(rd_example2)
    print(res)
