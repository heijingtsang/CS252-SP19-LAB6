#!/usr/bin/env python3
# print ("Hello World!")

# first parameter (String): the text that may contain to-be-censored words
# second parameter (List) : the list of blacklist words
def censorByWord(text, blacklist):
    textWords    = text.split()
    censoredText = []
    flag         = False

    # iterate for each word in textWords
    for word in textWords:
        # iterate for each censored word in blacklist
        for blacklistedWord in blacklist:
            if word == blacklistedWord:
                # replace the word with asterisk
                censoredText.append("*" * len(word))
                flag = True
                break
            else:
                # continue to the next iteration 
                continue

        # if word is not a blacklisted word
        if flag == False:
            censoredText.append(word)

        flag = False # set the flag to default

    # return the list censoredText as a string with spaces between each censoredText elements
    return " ".join(censoredText)


# first parameter (String): the text that may contain to-be-censored words
# second parameter (List) : the list of blacklist words
def censorBySubstring(text, blacklist):
    # String in python are immutable
    # iterate for each blacklistedWord in blacklist
    for blacklistedWord in blacklist:
        if text.find(blacklistedWord) != -1:
            text = text.replace(blacklistedWord, "*" * len(blacklistedWord))

    return text

def getBlacklistWordsFromFile(fileName):
    with open(fileName) as f:
        content = f.readlines()
        
    content = [x.strip() for x in content]

    return content




if __name__ == '__main__':
    # print ("Hello World in main!")
    # text = input("Enter your text: ").lower()
    # word = "one" # need to be a list
    # blacklist = ["one", "two", "three"]
    fileName = "blacklist.txt"
    blacklist = getBlacklistWordsFromFile(fileName)

    print ("the black listed words are: " + str(blacklist))

    # censoredText = censorByWord(text, blacklist)
    # censoredText = censorBySubstring(text, blacklist)
    # print ("CensoredText: " + censoredText)

