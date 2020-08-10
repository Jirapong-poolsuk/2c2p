import gnupg
from configparser import ConfigParser

#global Parameters
path = None
filePubKey = None
filePriKey = None
passPriKey = None

fileGACPriKey = None
passGACPriKey= None

pubKey = None
beginPubKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
endPubKey = '-----END PGP PUBLIC KEY BLOCK-----'

beginEncryptMsg = '-----BEGIN PGP MESSAGE-----'
endEncryptMsg = '-----END PGP MESSAGE-----'

gpg = gnupg.GPG()


def initConfig():
    #print('Initial Config...')
    config = ConfigParser()
    config.read('config.ini')

    global path,filePubKey,filePriKey,passPriKey, fileGACPriKey,passGACPriKey

    try:
        path = config['DEFAULT']['path']
    except:
        print('Config path not found')
        path = '/'

    try:
        filePubKey = config['DEFAULT']['filePubKey']
    except:
        print('Config filePubKey not found')

    try:
        filePriKey = config['DEFAULT']['filePriKey']
        passPriKey = config['DEFAULT']['passPriKey']
    except:
        print('Config filePriKey or passPriKey not found')

    try:
        fileGACPriKey = config['DEFAULT']['fileGACPriKey']
        passGACPriKey = config['DEFAULT']['passGACPriKey']
    except:
        print('Config fileGACPriKey or passGACPriKey not found')

    #print(' path %s' % path)
    #print(' file public key %s' % filePubKey)
    #print(' file private key %s' % filePriKey)
    #print(' password private key %s' % passPriKey)

    #print(' GAC file private key %s' % fileGACPriKey)
    #print(' GAC password private key %s' % passGACPriKey)


def importPublicKey():
    #print('Import Public Key')
    global gpg, pubKey, beginPubKey,endPubKey
    try:
        publicKey = open(path+filePubKey).read()

        if (beginPubKey in publicKey) is False:
            #print(' Apply header Public key')
            publicKey = beginPubKey+ '\n\n' + publicKey

        if (endPubKey in publicKey) is False:
            #print(' Apply footer Public key')
            publicKey = publicKey + '\n' + endPubKey

        import_result = gpg.import_keys(publicKey)
        #print(' import_result.results',import_result.results)
        #print(' import_result.fingerprints',import_result.fingerprints)
        pubKey = import_result.fingerprints[0]
        gpg.trust_keys(pubKey,'TRUST_ULTIMATE')
        #print('Import Public Key success!')
    except Exception as ex:
        print('Import Public Key exception', str(ex))


def importPrivateKey():
    #print('Import Private Key')
    global gpg, filePriKey
    try:
        with open(path+filePriKey, 'rb') as f:
          contents = f.read()
          gpg.import_keys(contents)
    except Exception as ex:
        print('Import Private Key exception', str(ex))


def importGACPrivateKey():
    #print('Import GAC Private Key')
    global gpg, fileGACPriKey
    try:
        with open(path+fileGACPriKey, 'rb') as f:
          contents = f.read()
          gpg.import_keys(contents)
    except Exception as ex:
        print('Import GAC Private Key exception', str(ex))


def encrypted(plainText):
    print('GPG encryption')
    global gpg, pubKey
    encrypted_string = None
    try:
        encrypted_data = gpg.encrypt(plainText, pubKey)
        if encrypted_data.ok is True:
            print(encrypted_data.status)
            encrypted_string = str(encrypted_data)
            if (beginEncryptMsg in encrypted_string) is True:
                print(' Apply header Public key')
                encrypted_string = encrypted_string[len(beginEncryptMsg + '\n\n'):]

            if (endEncryptMsg in encrypted_string) is True:
                print(' Apply footer Public key')
                encrypted_string = encrypted_string[:len(encrypted_string) - len('\n'+endEncryptMsg) - 2]
        else:
            encrypted_string = None
            print(encrypted_data.ok)
            print(encrypted_data.status)
            print(encrypted_data.stderr)
    except Exception as ex:
        print('GPG encryption fail', str(ex))
        encrypted_string = None

    print('return encrypted string',encrypted_string)
    return encrypted_string


def decrypted(encryptedData):
    print('GPG decryption')
    global gpg, passPriKey, beginEncryptMsg,endEncryptMsg
    decrypted_data = None
    if encryptedData is None:
        print('Input Encrypted Data is null')
        return decrypted_data
    try:
        if (beginEncryptMsg in encryptedData) is False:
            print(' Apply header Public key')
            encryptedData = beginEncryptMsg + '\n\n' + encryptedData

        if (endEncryptMsg in encryptedData) is False:
            print(' Apply footer Public key')
            encryptedData = encryptedData + '\n' + endEncryptMsg
    except Exception as ex:
        print('Apply header and footer encrypted Message fail', str(ex))

    try:
        decrypted_data = gpg.decrypt(encryptedData, passphrase=passPriKey)
        if decrypted_data.ok is True:
            print(decrypted_data.status)
        else:
            decrypted_data = None
            print(decrypted_data.ok)
            print(decrypted_data.status)
            print(decrypted_data.stderr)
    except Exception as ex:
        print('GPG decryption fail', str(ex))
        decrypted_data = None

    print('return decrypted_data', decrypted_data)
    return decrypted_data


def decByGAC(encryptedData):
    print('GPG decryption')
    global gpg, passGACPriKey, beginEncryptMsg, endEncryptMsg
    decrypted_data = None

    try:
        if (beginEncryptMsg in encryptedData) is False:
            print(' Apply header Public key')
            encryptedData = beginEncryptMsg + '\n\n' + encryptedData

        if (endEncryptMsg in encryptedData) is False:
            print(' Apply footer Public key')
            encryptedData = encryptedData + '\n' + endEncryptMsg
    except Exception as ex:
        print('Apply header and footer encrypted Message fail', str(ex))

    try:
        decrypted_data = gpg.decrypt(encryptedData,passphrase=passGACPriKey)
        if decrypted_data.ok is True:
            print(decrypted_data.status)
        else:
            decrypted_data = None
            print(decrypted_data.ok)
            print(decrypted_data.status)
            print(decrypted_data.stderr)
    except Exception as ex:
        print('GPG decryption fail', str(ex))
        decrypted_data = None

    print('return GPG decrypted_data', decrypted_data)
    return decrypted_data


def main():
    print('Import EncryptDecrypt.py')
    initConfig()
    importPublicKey()
    importPrivateKey()
    importGACPrivateKey()

    #test
    #print('Test')
    #testDecrypt = 'hQEMA7HUP/S/7UH8AQf/QvNZj2UMZ2T+eRcHU0yGruklBsjeFIXzb4bX8iI85blCVm/ehTrwbXi7jFZeXPkuLmusL5+TVtSFX+5aE/uqPX6+Umuw3FgkVv5wGb7sNNq1vhy0SvjPlxg4uMeK+b2iAvumJ0NBEpfiR3EPE5KP60qqvQRso2RLHMLUNVyErgIFQvRGeysjsbW0EGnQp+8v3rdQRc+v8F4jJ2tuB31KkKeXqRWEGF5eJdL2ctVSqv+ovU68U30yVrKHI+6xXs9m4QAjD8iSkYI2axE9VTPO16sCm0pPBwNES5Zx7AR702YmbUT3gTlcF/GwdxrUEenmDqf2GSJkuOmWNb50WZd2NdJrAeOchI7yMWkcQbLMLrUlgUefzv4Y9qMphkCpvcKDw4TuLXX0JND0RHrhT89ewEafrq2Hj+0frBfU+gTwLxmbYngQfngF9MfATLOq7hK4e7jE0V+heOE900RrGb/ktcKHfaiHfxwtTM2YU20==0rJ9'
    #testEncrypt = '{\"tsetsetsetset\":\"E01\",\"seesssssss\":\"Invalid request\"}'
    #resEn = encrypted(testEncrypt)
    #print('resEn',resEn)

    #resDeGAC = decByGAC(resEn)
    #print('resDeGAC',resDeGAC)

    #resDe = decrypted(testDecrypt)
    #print('resDe',resDe)


main()
#if __name__ == '__main__':
#    main()
