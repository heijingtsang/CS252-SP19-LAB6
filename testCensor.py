#!/usr/bin/env python3
# print ("Hello World!")

def censorByWord(text, word):
    t = text.split()
    n = []

    for i in t:
        if(i == word):
            n.append("*" * len(word))
        else:
            n.append(i)

    return " ".join(n)




if __name__ == '__main__':
    # print ("Hello World in main!")
    text = input("Enter your text: ").lower()
    word = "one" # need to be a list

    censoredText = censor(text, word)

    print ("CensoredText:" + censoredText)