from EncryptDecrypt import main, encrypted, decrypted, decByGAC

def main():
    print('Test')
    testDecrypt = 'hQEMA7HUP/S/7UH8AQf/QvNZj2UMZ2T+eRcHU0yGruklBsjeFIXzb4bX8iI85blCVm/ehTrwbXi7jFZeXPkuLmusL5+TVtSFX+5aE/uqPX6+Umuw3FgkVv5wGb7sNNq1vhy0SvjPlxg4uMeK+b2iAvumJ0NBEpfiR3EPE5KP60qqvQRso2RLHMLUNVyErgIFQvRGeysjsbW0EGnQp+8v3rdQRc+v8F4jJ2tuB31KkKeXqRWEGF5eJdL2ctVSqv+ovU68U30yVrKHI+6xXs9m4QAjD8iSkYI2axE9VTPO16sCm0pPBwNES5Zx7AR702YmbUT3gTlcF/GwdxrUEenmDqf2GSJkuOmWNb50WZd2NdJrAeOchI7yMWkcQbLMLrUlgUefzv4Y9qMphkCpvcKDw4TuLXX0JND0RHrhT89ewEafrq2Hj+0frBfU+gTwLxmbYngQfngF9MfATLOq7hK4e7jE0V+heOE900RrGb/ktcKHfaiHfxwtTM2YU20==0rJ9'
    testEncrypt = '{\"tsetsetsetset\":\"E01\",\"seesssssss\":\"Invalid request\"}'
    resEn = encrypted(testEncrypt)
    print('resEn',resEn)

    resDeGAC = decByGAC(resEn)
    print('resDeGAC',resDeGAC)

    resDe = decrypted(testDecrypt)
    print('resDe',resDe)

if __name__ == '__main__':
    main()
