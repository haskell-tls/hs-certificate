-- | x509-store test suite.
module Main (main) where

import qualified Data.ByteString as B
import           Data.String (fromString)
import           Data.X509
import           Data.X509.Memory

import Test.Tasty
import Test.Tasty.HUnit

{-
  openssl req -new -x509 -subj /CN=Test -newkey rsa:1024 -nodes -reqexts v3_req \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
  sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/' privkey.pem
  openssl rsa -in privkey.pem | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
-}
rsaCertificate, rsaKey1, rsaKey2 :: B.ByteString
rsaCertificate = fromString $
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIIB7DCCAVWgAwIBAgIJAPmzhcKJcLZtMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV\n" ++
    "BAMMBFRlc3QwHhcNMTcwMzAyMTgwODU3WhcNMTcwNDAxMTgwODU3WjAPMQ0wCwYD\n" ++
    "VQQDDARUZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzkysIZyZ1UYFl\n" ++
    "OFKOhZ+T7Usgove7Z9z9zBSXM7ufXl5NF5QV+u76bDo5ITD81NYiqCLoNGRVC1FY\n" ++
    "srVmx97AyqQ6Hj2IGfar2JyymTO2Y4E7kYO21hxJSrIJOVnAbGdxHYwiKVFZkP5g\n" ++
    "PS5FzYqwfMet4gpbPJcvBjfZVo2MIQIDAQABo1AwTjAdBgNVHQ4EFgQUhJgtg9dO\n" ++
    "jcpA08w0BuXptQw+JVkwHwYDVR0jBBgwFoAUhJgtg9dOjcpA08w0BuXptQw+JVkw\n" ++
    "DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQA2OIHfXV9Ro7208mNaz6Bi\n" ++
    "QYhW4gGbQA6/5N/BYby5kHLC+veJ9qAXjILn5qW5hsuf4X4Nq7VO3HKQ89Jo2COc\n" ++
    "6fAvjhCWKqlZFAIBKbcEcg3QZqAdXJ4Q8RLMvG3y/vDzixp1Xuxk0Zbr88D7SX7i\n" ++
    "Lx+S385X8OT7Wiu6qhM6ig==\n" ++
    "-----END CERTIFICATE-----\n"
rsaKey1 = fromString $
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALOTKwhnJnVRgWU4\n" ++
    "Uo6Fn5PtSyCi97tn3P3MFJczu59eXk0XlBX67vpsOjkhMPzU1iKoIug0ZFULUViy\n" ++
    "tWbH3sDKpDoePYgZ9qvYnLKZM7ZjgTuRg7bWHElKsgk5WcBsZ3EdjCIpUVmQ/mA9\n" ++
    "LkXNirB8x63iCls8ly8GN9lWjYwhAgMBAAECgYAxGVkXyBRU2X82rMqt201Bhg0X\n" ++
    "lFeF7yUWY7lxihyPu56vF3ZO+DhlUjgtLK0XRB50hWJd+Q1Bz4FjbiF5Q8bcm/rz\n" ++
    "4BzyojpoCHoMnrcPyP+7+LE50MFsySvjQWCJkz0WSoFBsoEVQOvkAkhCEiR4vqoJ\n" ++
    "UNjZczb2PAvWjlUsvQJBAOyLOm+P4RnrRaV/dMXx3pfNTolJp7KQ0zXghKc4clF5\n" ++
    "ESMsWHwHRGU++/tW90m/j8ApDvlIrXTmYOyQ4jKCCk8CQQDCWGAzeVa4xL+p2SaO\n" ++
    "TP5aqRjfEIVf0O3HjB9GklrdwtnDF4JrUUILdUKJ3qxqEetNpSZjzc3H6dDtxvy1\n" ++
    "yRaPAkEAp+fMexRufK98qJVolnmxv5+Ed/9IgoA67KuKfgibXSnK+GSqCqA99IBY\n" ++
    "7Xg14KuRpp1+e4UTWz+M3V+asK+OEQJBAKvQW8RGCqAw+M0c+FQnx1q5Ug6q2W77\n" ++
    "E6wtudy3OPQC9mfemeNspDnjAd9HaCAiFWfAkK79XGbX1GjSWcoQrAsCQQDRoscG\n" ++
    "Udtf0rxGk4y79YNXPeTReF+0wCdWdDNpAdnhpYCnFE+74LyiY8YRbfe2jP7X2uyn\n" ++
    "/h1HwfRSKCZ7Epcv\n" ++
    "-----END PRIVATE KEY-----\n"
rsaKey2 = fromString $
    "-----BEGIN RSA PRIVATE KEY-----\n" ++
    "MIICXgIBAAKBgQCzkysIZyZ1UYFlOFKOhZ+T7Usgove7Z9z9zBSXM7ufXl5NF5QV\n" ++
    "+u76bDo5ITD81NYiqCLoNGRVC1FYsrVmx97AyqQ6Hj2IGfar2JyymTO2Y4E7kYO2\n" ++
    "1hxJSrIJOVnAbGdxHYwiKVFZkP5gPS5FzYqwfMet4gpbPJcvBjfZVo2MIQIDAQAB\n" ++
    "AoGAMRlZF8gUVNl/NqzKrdtNQYYNF5RXhe8lFmO5cYocj7uerxd2Tvg4ZVI4LSyt\n" ++
    "F0QedIViXfkNQc+BY24heUPG3Jv68+Ac8qI6aAh6DJ63D8j/u/ixOdDBbMkr40Fg\n" ++
    "iZM9FkqBQbKBFUDr5AJIQhIkeL6qCVDY2XM29jwL1o5VLL0CQQDsizpvj+EZ60Wl\n" ++
    "f3TF8d6XzU6JSaeykNM14ISnOHJReREjLFh8B0RlPvv7VvdJv4/AKQ75SK105mDs\n" ++
    "kOIyggpPAkEAwlhgM3lWuMS/qdkmjkz+WqkY3xCFX9Dtx4wfRpJa3cLZwxeCa1FC\n" ++
    "C3VCid6sahHrTaUmY83Nx+nQ7cb8tckWjwJBAKfnzHsUbnyvfKiVaJZ5sb+fhHf/\n" ++
    "SIKAOuyrin4Im10pyvhkqgqgPfSAWO14NeCrkaadfnuFE1s/jN1fmrCvjhECQQCr\n" ++
    "0FvERgqgMPjNHPhUJ8dauVIOqtlu+xOsLbnctzj0AvZn3pnjbKQ54wHfR2ggIhVn\n" ++
    "wJCu/Vxm19Ro0lnKEKwLAkEA0aLHBlHbX9K8RpOMu/WDVz3k0XhftMAnVnQzaQHZ\n" ++
    "4aWApxRPu+C8omPGEW33toz+19rsp/4dR8H0UigmexKXLw==\n" ++
    "-----END RSA PRIVATE KEY-----\n"

{-
  openssl dsaparam 1024 -out dsaparams
  openssl req -new -x509 -subj /CN=Test -newkey dsa:dsaparams -nodes -reqexts v3_req \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
  sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'  privkey.pem
  openssl dsa -in privkey.pem | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
-}
dsaCertificate, dsaKey1, dsaKey2 :: B.ByteString
dsaCertificate = fromString $
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIICrzCCAmugAwIBAgIJALFEpgowHmcXMAsGCWCGSAFlAwQDAjAPMQ0wCwYDVQQD\n" ++
    "DARUZXN0MB4XDTE3MDMwMjE4MTA0OFoXDTE3MDQwMTE4MTA0OFowDzENMAsGA1UE\n" ++
    "AwwEVGVzdDCCAbYwggErBgcqhkjOOAQBMIIBHgKBgQCsH77mdMUYCgpdNnqljOoG\n" ++
    "OLOkPb+9pIrV/LWoX9TvhyfoVOJli5dEWqcui9eTZZ4LW+2F1//0HpTjW5d+aZk7\n" ++
    "znkSRg9yihhzYzqGL7GEinFGHIPBL5uKoCW7a2HlJ+OdLBNQ/yeCDpTvt+/agLlA\n" ++
    "K1CgpBd1NeG7jFmfgmJ+gwIVAOs+Q1CAhIZzqH7Ymgp4X2buU1plAoGALiXg/kXS\n" ++
    "DSWVzbP6kEKMjkpc0KMmUQCErJgcTZmqe2IddoghCHq44ofbdMyJivk0V3lAfprP\n" ++
    "l2LMKKnwc0NgWEcPPmR+ZyYXODxOeXlZd1qznDKWdvpciOkMdWOsxF+cbtmGBrxs\n" ++
    "+Rm86f+95+EsptH/8FeLFMw7L8u/0FNgAyoDgYQAAoGAIBhO3gbkWHsZSic+5rdh\n" ++
    "HS0z0h/kBqbqY2BHFXchaMAgzMrzD/rTpeZ+mND8tIRzOw73tKckeHrfauBNPstc\n" ++
    "c2SCFy9lc7eITD/HmoCJFuMLbYxpWlOYL5JU5EQT/1VlH58RprfMp5+HA1tSMZov\n" ++
    "zf7ck2W7Rt6zH77Io5lt0aujUDBOMB0GA1UdDgQWBBQOlmp9KHZbomx3TbKxBiGL\n" ++
    "oVUB1zAfBgNVHSMEGDAWgBQOlmp9KHZbomx3TbKxBiGLoVUB1zAMBgNVHRMEBTAD\n" ++
    "AQH/MAsGCWCGSAFlAwQDAgMxADAuAhUAp/XUpSnDENVgqr2MS1XCXHjI9kACFQDq\n" ++
    "jV1C0EYgKTRYKjrztFjBEHv3Ig==\n" ++
    "-----END CERTIFICATE-----\n"
dsaKey1 = fromString $
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBAKwfvuZ0xRgKCl02eqWM6gY4s6Q9\n" ++
    "v72kitX8tahf1O+HJ+hU4mWLl0Rapy6L15Nlngtb7YXX//QelONbl35pmTvOeRJG\n" ++
    "D3KKGHNjOoYvsYSKcUYcg8Evm4qgJbtrYeUn450sE1D/J4IOlO+379qAuUArUKCk\n" ++
    "F3U14buMWZ+CYn6DAhUA6z5DUICEhnOoftiaCnhfZu5TWmUCgYAuJeD+RdINJZXN\n" ++
    "s/qQQoyOSlzQoyZRAISsmBxNmap7Yh12iCEIerjih9t0zImK+TRXeUB+ms+XYswo\n" ++
    "qfBzQ2BYRw8+ZH5nJhc4PE55eVl3WrOcMpZ2+lyI6Qx1Y6zEX5xu2YYGvGz5Gbzp\n" ++
    "/73n4Sym0f/wV4sUzDsvy7/QU2ADKgQWAhQ/q2pbQjljQ7CD3Uc6FA63FS7fYg==\n" ++
    "-----END PRIVATE KEY-----\n"
dsaKey2 = fromString $
    "-----BEGIN DSA PRIVATE KEY-----\n" ++
    "MIIBugIBAAKBgQCsH77mdMUYCgpdNnqljOoGOLOkPb+9pIrV/LWoX9TvhyfoVOJl\n" ++
    "i5dEWqcui9eTZZ4LW+2F1//0HpTjW5d+aZk7znkSRg9yihhzYzqGL7GEinFGHIPB\n" ++
    "L5uKoCW7a2HlJ+OdLBNQ/yeCDpTvt+/agLlAK1CgpBd1NeG7jFmfgmJ+gwIVAOs+\n" ++
    "Q1CAhIZzqH7Ymgp4X2buU1plAoGALiXg/kXSDSWVzbP6kEKMjkpc0KMmUQCErJgc\n" ++
    "TZmqe2IddoghCHq44ofbdMyJivk0V3lAfprPl2LMKKnwc0NgWEcPPmR+ZyYXODxO\n" ++
    "eXlZd1qznDKWdvpciOkMdWOsxF+cbtmGBrxs+Rm86f+95+EsptH/8FeLFMw7L8u/\n" ++
    "0FNgAyoCgYAgGE7eBuRYexlKJz7mt2EdLTPSH+QGpupjYEcVdyFowCDMyvMP+tOl\n" ++
    "5n6Y0Py0hHM7Dve0pyR4et9q4E0+y1xzZIIXL2Vzt4hMP8eagIkW4wttjGlaU5gv\n" ++
    "klTkRBP/VWUfnxGmt8ynn4cDW1Ixmi/N/tyTZbtG3rMfvsijmW3RqwIUP6tqW0I5\n" ++
    "Y0Owg91HOhQOtxUu32I=\n" ++
    "-----END DSA PRIVATE KEY-----\n"

{-
  openssl ecparam -name prime256v1 -out ecparams -param_enc named_curve
  openssl req -new -x509 -subj /CN=Test -newkey ec:ecparams -nodes -reqexts v3_req \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
  sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'  privkey.pem
  openssl ec -in privkey.pem | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
-}
ecCertificateNc, ecKey1Nc, ecKey2Nc :: B.ByteString
ecCertificateNc = fromString $
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIIBZTCCAQugAwIBAgIJAPF7NB8WKn6XMAoGCCqGSM49BAMCMA8xDTALBgNVBAMM\n" ++
    "BFRlc3QwHhcNMTcwMzAyMTgxMTI1WhcNMTcwNDAxMTgxMTI1WjAPMQ0wCwYDVQQD\n" ++
    "DARUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETCmVJNQ5HWoFKMpyZFly\n" ++
    "kILKFuE0ZTu2t8G5jXpQp0g4g8OqyRo/6iSZSs/WAP3e2vcJuyhnDSd8MocSnEfi\n" ++
    "pqNQME4wHQYDVR0OBBYEFKCemJ7KZ+JfExQxOh/0qhKO3cJwMB8GA1UdIwQYMBaA\n" ++
    "FKCemJ7KZ+JfExQxOh/0qhKO3cJwMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwID\n" ++
    "SAAwRQIhALhWJShVXsrupU8ISSBJVGmzRhPcueHsjuydyyfOsxElAiADbsp0SM/9\n" ++
    "6CQCvqX+V8DAwxT1WiRDzN8ilV6ZIfUI3Q==\n" ++
    "-----END CERTIFICATE-----\n"
ecKey1Nc = fromString $
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1hT2Mdt5IS0Qs9Bb\n" ++
    "LJ8ZAW3VTDIq1zn8qSYGiLcMVkShRANCAARMKZUk1DkdagUoynJkWXKQgsoW4TRl\n" ++
    "O7a3wbmNelCnSDiDw6rJGj/qJJlKz9YA/d7a9wm7KGcNJ3wyhxKcR+Km\n" ++
    "-----END PRIVATE KEY-----\n"
ecKey2Nc = fromString $
    "-----BEGIN EC PRIVATE KEY-----\n" ++
    "MHcCAQEEINYU9jHbeSEtELPQWyyfGQFt1UwyKtc5/KkmBoi3DFZEoAoGCCqGSM49\n" ++
    "AwEHoUQDQgAETCmVJNQ5HWoFKMpyZFlykILKFuE0ZTu2t8G5jXpQp0g4g8OqyRo/\n" ++
    "6iSZSs/WAP3e2vcJuyhnDSd8MocSnEfipg==\n" ++
    "-----END EC PRIVATE KEY-----\n"

{-
  openssl ecparam -name prime256v1 -out ecparams -param_enc explicit
  openssl req -new -x509 -subj /CN=Test -newkey ec:ecparams -nodes -reqexts v3_req \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
  sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'  privkey.pem
  openssl ec -in privkey.pem | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
-}
ecCertificateEpc, ecKey1Epc, ecKey2Epc :: B.ByteString
ecCertificateEpc = fromString $
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIICWTCCAf+gAwIBAgIJAPF9pxfJTwfaMAoGCCqGSM49BAMCMA8xDTALBgNVBAMM\n" ++
    "BFRlc3QwHhcNMTcwMzAyMTgxMTUxWhcNMTcwNDAxMTgxMTUxWjAPMQ0wCwYDVQQD\n" ++
    "DARUZXN0MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8A\n" ++
    "AAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAA\n" ++
    "AAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9Jg\n" ++
    "SwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n" ++
    "6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP//\n" ++
    "//8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABHXlHgRztuAF/Vs5\n" ++
    "GMB5GEfGpFsSsua+GDB8/zvjT4UBgpnb71HJPFOC0yrYliunXds00VlOs3v+FCVL\n" ++
    "mU5yW+2jUDBOMB0GA1UdDgQWBBSFV0KwoW1mPah12w3rngU7t1kjETAfBgNVHSME\n" ++
    "GDAWgBSFV0KwoW1mPah12w3rngU7t1kjETAMBgNVHRMEBTADAQH/MAoGCCqGSM49\n" ++
    "BAMCA0gAMEUCIDqqWyJEIRo2YSvvrQKJZ3wKQSGeWoPnJvWfXMjgODd5AiEAsXCt\n" ++
    "LYmBKulTMXATynvrqa/xDi3z2lkwcWQC1AZBZ8M=\n" ++
    "-----END CERTIFICATE-----\n"
ecKey1Epc = fromString $
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MIIBeQIBADCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAAB\n" ++
    "AAAAAAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA\n" ++
    "///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMV\n" ++
    "AMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg\n" ++
    "9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8A\n" ++
    "AAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBG0wawIBAQQgBnbFaCHgp5Cn\n" ++
    "stu9ntk7QiEP6j/7FzK6GC4dzsID7/ihRANCAAR15R4Ec7bgBf1bORjAeRhHxqRb\n" ++
    "ErLmvhgwfP8740+FAYKZ2+9RyTxTgtMq2JYrp13bNNFZTrN7/hQlS5lOclvt\n" ++
    "-----END PRIVATE KEY-----\n"
ecKey2Epc = fromString $
    "-----BEGIN EC PRIVATE KEY-----\n" ++
    "MIIBaAIBAQQgBnbFaCHgp5Cnstu9ntk7QiEP6j/7FzK6GC4dzsID7/iggfowgfcC\n" ++
    "AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////\n" ++
    "MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr\n" ++
    "vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE\n" ++
    "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W\n" ++
    "K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8\n" ++
    "YyVRAgEBoUQDQgAEdeUeBHO24AX9WzkYwHkYR8akWxKy5r4YMHz/O+NPhQGCmdvv\n" ++
    "Uck8U4LTKtiWK6dd2zTRWU6ze/4UJUuZTnJb7Q==\n" ++
    "-----END EC PRIVATE KEY-----\n"

{-
  openssl req -new -x509 -subj /CN=CA -newkey rsa:1024 -nodes -reqexts v3_ca \
      -keyout cakey.pem -out cacert.pem
  openssl req -new -subj /CN=Test -key cakey.pem -nodes -reqexts v3_req \
      -out req.pem
  openssl genpkey -algorithm x25519 -out privkey.pem
  openssl pkey -in privkey.pem -pubout -out pubkey.pem
  openssl x509 -req -in req.pem -CA cacert.pem -CAkey cakey.pem \
      -set_serial 2 -force_pubkey pubkey.pem \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
  sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'  privkey.pem
  openssl pkey -in privkey.pem -traditional \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
-}
x25519Certificate, x25519Key1, x25519Key2 :: B.ByteString
x25519Certificate = fromString $
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIIBEzB+AgECMA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNVBAMMAkNBMB4XDTE4MDgy\n" ++
    "NjE0MTIzOFoXDTE4MDkyNTE0MTIzOFowDzENMAsGA1UEAwwEVGVzdDAqMAUGAytl\n" ++
    "bgMhAMzDmaCSEjQR6yWKSdWBxw4YNOb6YMETiWt7AVOUaxw9MA0GCSqGSIb3DQEB\n" ++
    "CwUAA4GBAEJrXXtt9XaL3oARVv8hm/abqhUds9ytT4CQtaQgSV7HQIp96LN87pc9\n" ++
    "pwrISZrWuIlVpyQpGOK1i+uI3LgdKn1zO5CJdjRtW6lCCXg9R/wEcEKAiVKIzg2G\n" ++
    "FanQ4TG8YzfBToUbsSMfptxhbKPk/lVa8ffmXLZBILjPbI63iu4d\n" ++
    "-----END CERTIFICATE-----\n"
x25519Key1 = fromString $
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MC4CAQAwBQYDK2VuBCIEIEhpc79EOwSU0JgHC6/32OUYul2yRiha3aftJiHybq1F\n" ++
    "-----END PRIVATE KEY-----\n"
x25519Key2 = fromString $
    "-----BEGIN X25519 PRIVATE KEY-----\n" ++
    "MC4CAQAwBQYDK2VuBCIEIEhpc79EOwSU0JgHC6/32OUYul2yRiha3aftJiHybq1F\n" ++
    "-----END X25519 PRIVATE KEY-----\n"

{-
  openssl req -new -x509 -subj /CN=CA -newkey rsa:1024 -nodes -reqexts v3_ca \
      -keyout cakey.pem -out cacert.pem
  openssl req -new -subj /CN=Test -key cakey.pem -nodes -reqexts v3_req \
      -out req.pem
  openssl genpkey -algorithm x448 -out privkey.pem
  openssl pkey -in privkey.pem -pubout -out pubkey.pem
  openssl x509 -req -in req.pem -CA cacert.pem -CAkey cakey.pem \
      -set_serial 2 -force_pubkey pubkey.pem \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
  sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'  privkey.pem
  openssl pkey -in privkey.pem -traditional \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
-}
x448Certificate, x448Key1, x448Key2 :: B.ByteString
x448Certificate = fromString $
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIIBLDCBlgIBAjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDDAJDQTAeFw0xODA4\n" ++
    "MjYxNDEzMTlaFw0xODA5MjUxNDEzMTlaMA8xDTALBgNVBAMMBFRlc3QwQjAFBgMr\n" ++
    "ZW8DOQCh0ta92rVURtIK29lN9F1QbBpSV0jAr7jAXLdz4SHPPO1OO+2gXvjuDpt3\n" ++
    "lTzR6oZQkAc5nK43PjANBgkqhkiG9w0BAQsFAAOBgQCk2dVKQpLS4/EEe2fuRMvs\n" ++
    "2qvERTT41P9cjkz3obrizjg68Aaj1m/0SeQFWYh4QeGf7lVSA6evPQG8XdscHHMd\n" ++
    "/7/U/gfY+aTiaKTf/E7pXMdtiMEOkcrA1J5fnI5M96R6UMRIRbqxhpGC/Jb7EdVM\n" ++
    "LAlOqcCwRBVCEJnexQK1TA==\n" ++
    "-----END CERTIFICATE-----\n"
x448Key1 = fromString $
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MEYCAQAwBQYDK2VvBDoEOKxpGvu6rhYy78qgxgtT+uZt4Ctxd3AB/S59i1Cx03hR\n" ++
    "kVB9q7Mz02YjHbwAaM/hAHajYdwHa7aV\n" ++
    "-----END PRIVATE KEY-----\n"
x448Key2 = fromString $
    "-----BEGIN X448 PRIVATE KEY-----\n" ++
    "MEYCAQAwBQYDK2VvBDoEOKxpGvu6rhYy78qgxgtT+uZt4Ctxd3AB/S59i1Cx03hR\n" ++
    "kVB9q7Mz02YjHbwAaM/hAHajYdwHa7aV\n" ++
    "-----END X448 PRIVATE KEY-----\n"

{-
  openssl req -new -x509 -subj /CN=Test -newkey ed25519 -nodes -reqexts v3_req \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
  sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'  privkey.pem
  openssl pkey -in privkey.pem -traditional \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
-}
ed25519Certificate, ed25519Key1, ed25519Key2 :: B.ByteString
ed25519Certificate = fromString $
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIIBMjCB5aADAgECAhR6ecRAmI54Nv+XftTZ/GSiPICx0TAFBgMrZXAwDzENMAsG\n" ++
    "A1UEAwwEVGVzdDAeFw0xODA4MTUxMTQ3MDNaFw0xODA5MTQxMTQ3MDNaMA8xDTAL\n" ++
    "BgNVBAMMBFRlc3QwKjAFBgMrZXADIQAI0GFxXxlCuJD082Grn0p0AZ/staBylKsS\n" ++
    "OwPu6iPHb6NTMFEwHQYDVR0OBBYEFGTOlalKBchEtrbeG5jRF5fbzhDJMB8GA1Ud\n" ++
    "IwQYMBaAFGTOlalKBchEtrbeG5jRF5fbzhDJMA8GA1UdEwEB/wQFMAMBAf8wBQYD\n" ++
    "K2VwA0EARON+KCuJoY1u8Yrn/MrCBpeu49AIMbqoyB8YN6msQpLPjWzLYaC70Cc2\n" ++
    "DY6BFI5hKr+mLCN/+VlzRzqW8dqSDg==\n" ++
    "-----END CERTIFICATE-----\n"
ed25519Key1 = fromString $
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MC4CAQAwBQYDK2VwBCIEILEtRbG7T++/S58HPwVUJSR12Iu8FVputSfQBkotgeZ0\n" ++
    "-----END PRIVATE KEY-----\n"
ed25519Key2 = fromString $
    "-----BEGIN ED25519 PRIVATE KEY-----\n" ++
    "MC4CAQAwBQYDK2VwBCIEILEtRbG7T++/S58HPwVUJSR12Iu8FVputSfQBkotgeZ0\n" ++
    "-----END ED25519 PRIVATE KEY-----\n"

{-
  openssl req -new -x509 -subj /CN=Test -newkey ed448 -nodes -reqexts v3_req \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
  sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'  privkey.pem
  openssl pkey -in privkey.pem -traditional \
      | sed -e 's/^\(.*\)$/    "\1\\n"/' -e '$!s/$/ ++/'
-}
ed448Certificate, ed448Key1, ed448Key2 :: B.ByteString
ed448Certificate = fromString $
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIIBfTCB/qADAgECAhQ4hHMRAtg46drqmq6GQxeDN1WScDAFBgMrZXEwDzENMAsG\n" ++
    "A1UEAwwEVGVzdDAeFw0xODA4MTUxMTQ1MzRaFw0xODA5MTQxMTQ1MzRaMA8xDTAL\n" ++
    "BgNVBAMMBFRlc3QwQzAFBgMrZXEDOgBMbAytTVwKE9JHijqIy1q+wgs/G235N2w9\n" ++
    "Hfai1DjPd5nyVDeSD+BHiuJZDWfxRe6y34seoIsszQCjUzBRMB0GA1UdDgQWBBQo\n" ++
    "Nz/cV3FL07M93xsySVPHD0nOojAfBgNVHSMEGDAWgBQoNz/cV3FL07M93xsySVPH\n" ++
    "D0nOojAPBgNVHRMBAf8EBTADAQH/MAUGAytlcQNzABqXoKLJjmHK+smSGeh5M0vU\n" ++
    "PbHM3oSuiS25Q5UqHnrrxgyVBvq83/jCpEHc03BOSrMU5fRhbc84AK1kAPeEdGns\n" ++
    "dsG2uVxz0be795jKStt0a0o/w9cN5bd761Oeqoqs8CxWtjALhLu27IiY5uRkG5Uq\n" ++
    "AA==\n" ++
    "-----END CERTIFICATE-----\n"
ed448Key1 = fromString $
    "-----BEGIN PRIVATE KEY-----\n" ++
    "MEcCAQAwBQYDK2VxBDsEOcYO2tQ1U1vNoCUT0bNXVeausDEkUMmN0RI4ZUWU+9jA\n" ++
    "ZxaQP40ONQ5yQM/V6Nuw3NlDnp8OU9R18Q==\n" ++
    "-----END PRIVATE KEY-----\n"
ed448Key2 = fromString $
    "-----BEGIN ED448 PRIVATE KEY-----\n" ++
    "MEcCAQAwBQYDK2VxBDsEOcYO2tQ1U1vNoCUT0bNXVeausDEkUMmN0RI4ZUWU+9jA\n" ++
    "ZxaQP40ONQ5yQM/V6Nuw3NlDnp8OU9R18Q==\n" ++
    "-----END ED448 PRIVATE KEY-----\n"

memoryKeyTests :: TestTree
memoryKeyTests = testGroup "Key"
    [ keyTest "RSA"                        rsaKey1      rsaKey2
    , keyTest "DSA"                        dsaKey1      dsaKey2
    , keyTest "EC (named curve)"           ecKey1Nc     ecKey2Nc
    , keyTest "EC (explicit prime curve)"  ecKey1Epc    ecKey2Epc
    , keyTest "X25519"                     x25519Key1   x25519Key2
    , keyTest "X448"                       x448Key1     x448Key2
    , keyTest "Ed25519"                    ed25519Key1  ed25519Key2
    , keyTest "Ed448"                      ed448Key1    ed448Key2
    ]
  where
    keyTest name outer inner =
        let kInner = readKeyFileFromMemory inner
            kOuter = readKeyFileFromMemory outer
         in testGroup name
                [ testCase "read outer" $ length kOuter @?= 1
                , testCase "read inner" $ length kInner @?= 1
                , testCase "same key"   $
                      assertBool "keys differ" (kInner == kOuter)
                ]

memoryCertificateTests :: TestTree
memoryCertificateTests = testGroup "Certificate"
    [ certTest "RSA"                        rsaCertificate
    , certTest "DSA"                        dsaCertificate
    , certTest "EC (named curve)"           ecCertificateNc
    , certTest "EC (explicit prime curve)"  ecCertificateEpc
    , certTest "X25519"                     x25519Certificate
    , certTest "X448"                       x448Certificate
    , certTest "Ed25519"                    ed25519Certificate
    , certTest "Ed448"                      ed448Certificate
    ]
  where
    certTest name bytes = testCase name $
        length (readSignedCertificateFromMemory bytes) @?= 1

    readSignedCertificateFromMemory :: B.ByteString -> [SignedCertificate]
    readSignedCertificateFromMemory = readSignedObjectFromMemory

-- | Runs the test suite.
main :: IO ()
main = defaultMain $ testGroup "x509-store"
    [ testGroup "Memory"
          [ memoryKeyTests
          , memoryCertificateTests
          ]
    ]
