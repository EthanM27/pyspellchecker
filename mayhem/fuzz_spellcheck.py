#! /usr/bin/python3

import atheris
import sys
import asyncio

with atheris.instrument_imports():
    from spellchecker import SpellChecker

english = SpellChecker()  # the default is English (language='en')
spanish = SpellChecker(language='es') 
french = SpellChecker(language='fr') 
portuguese = SpellChecker(language='pt')
german = SpellChecker(language='de')
russian = SpellChecker(language='ru')
arabic = SpellChecker(language='ar')

langs = [english,
         spanish, 
         french, 
         portuguese, 
         german, 
         russian,
         arabic]

@atheris.instrument_func
def test_known_unknown(data):
    fdp = atheris.FuzzedDataProvider(data)
    s = fdp.ConsumeBytes(4096)

    for lang in langs:
        known = len(lang.known([s]))
        unknown = len(lang.unknown([s]))

        if (known > 0) and (unknown > 0):
            if known == unknown:
                print(s)
                raise Exception("test case is both known and unknown")
                # if the input data is both known and unknown by the dictionary,
                # this should be an error

@atheris.instrument_func
def test_possible_corrections(data):    
    fdp = atheris.FuzzedDataProvider(data)
    s = fdp.ConsumeUnicode(4096)

    for lang in langs:
        lang.candidates(s)

def main():
    atheris.Setup(sys.argv, test_known_unknown)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
