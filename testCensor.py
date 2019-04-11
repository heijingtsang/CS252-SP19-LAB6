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


def censorBySubstring(text, word):
    pass



if __name__ == '__main__':
    # print ("Hello World in main!")
    text = input("Enter your text: ").lower()
    word = "one" # need to be a list
    blacklist = ["one", "two", "three"]

    censoredText = censorByWord(text, blacklist)

    print ("CensoredText: " + censoredText)