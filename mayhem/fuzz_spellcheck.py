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

# add support for testing multiple languages.
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
    s = fdp.ConsumeUnicode(4096)

    # tests the known and unknown functions directly, which adds to the functions tested
    # in the original
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
        # only needs to test candidates and not correction bc 
        # correction only adds an additional list sort overhead while still using
        # candidates. Speeds up runtime
        lang.candidates(s)

def main():
    atheris.Setup(sys.argv, test_known_unknown)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
