import crypt
def testpassword(cryptpassword):
    salt =cryptpassword[0:2]
    dictionaryfile=open('dictionary.txt','r')
    for word in dictionaryfile.readlines():
        word=word.strip('\n')
        cryptword=crypt.crypt(word,salt)
        if (cryptword == cryptpassword):
            print('[+] found password: ' + word + '\n' )
            return
    print('[-] password not found.\n')
    return
def main():
    passwordfile=open('passwords.txt')
    for line in passwordfile.readlines():
        if ':' in line:
            user=line.split(':')[0]
            cryptpassword=line.split(':')[1].split(' ')
            print('[*] cracking password for: ' + user)
testpassword(cryptpassword)
if __name__ == "__main__":
    main()